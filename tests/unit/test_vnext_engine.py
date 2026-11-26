"""Comprehensive N1 unit tests for ControlBot vNext M3 core modules."""

from __future__ import annotations

import asyncio
import json
import shlex
import signal
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from src.adapters.config import AreaConfig, AssetMapping, FacilityConfig, load_facility_config
from src.adapters.office_excel import (
    ExcelCellSpec,
    ExcelSheetSpec,
    OfficeExcelBuilder,
    read_workbook_ooxml,
)
from src.adapters.web_search import EgressBlockedError, EgressGuard, HttpWebFetcher, WebPageExtract
from src.contracts.enums import DataQuality
from src.contracts.envelope import (
    ActorContext,
    AirlockProvenance,
    Lane,
    TaskEnvelope,
    VerdictState,
    VerifiedResponseMeta,
)
from src.contracts.models import EvidenceRequirements, Observation, TaskScope, TaskSpec
from src.engine.airlock import (
    AirlockBlockedError,
    EvidenceAirlock,
    build_airlock_provenance,
)
from src.engine.policy_gateway import (
    PolicyGateway,
    PolicyRequest,
    PolicyRule,
    PolicySet,
    _fast_posix_shlex_split,
    _find_python_c_script,
    _find_sh_c_script_index,
    safety_floor,
    sanitize_audit_arguments,
)
from src.engine.router import LaneRouter
from src.engine.verifiers import (
    AssetResolver,
    ClaimedSpecField,
    FreshnessPolicy,
    HealthGuard,
    IndustrialReconciler,
    SpreadsheetVerifier,
    WebCitationVerifier,
    normalize_unit_and_value,
)


def _sample_facility() -> FacilityConfig:
    return FacilityConfig(
        facility_id="facility-a",
        facility_name="Planta Piloto A",
        areas={
            "area-1": AreaConfig(display_name="Línea 1"),
            "area-2": AreaConfig(display_name="Línea 2"),
        },
        assets=(
            AssetMapping(
                asset_id="pump-34-a1",
                area="area-1",
                canonical_label="Bomba 34",
                aliases=("P-34A", "Bomba 34 L1"),
                allowed_units={"reading": ("bar",)},
                source_ids={"scada": "SCADA-P34-A1", "maintenance": "CMMS-P34-A1"},
            ),
            AssetMapping(
                asset_id="pump-34-a2",
                area="area-2",
                canonical_label="Bomba 34",
                aliases=("P-34B", "Bomba 34 L2"),
                allowed_units={"reading": ("bar",)},
                source_ids={"scada": "SCADA-P34-A2", "maintenance": "CMMS-P34-A2"},
            ),
            AssetMapping(
                asset_id="tt-402b",
                area="area-1",
                canonical_label="Transmisor TT-402B",
                aliases=("TT-402B",),
                allowed_units={"reading": ("C", "°C")},
                source_ids={"scada": "SCADA-TT402B"},
            ),
        ),
    )


@pytest.mark.n1
def test_task_envelope_general_no_facility_and_industrial_fail_closed() -> None:
    actor = ActorContext(user_id="op-1", profile_id="prof-1", role="operator")
    env = TaskEnvelope(
        task_id="env-gen-1",
        lane=Lane.GENERAL,
        actor=actor,
        query="Summarize Q3 budget workbook",
        budget_root_id="root-1",
    )
    assert env.facility_id is None
    legacy = env.to_legacy_task_spec()
    assert legacy.scope.facility_id == "general-sandbox"

    roundtrip = TaskEnvelope.from_task_spec(legacy)
    assert roundtrip.lane == Lane.INDUSTRIAL
    assert roundtrip.actor.user_id == "op-1"

    with pytest.raises(ValidationError):
        TaskEnvelope(
            task_id="env-ind-write",
            lane=Lane.INDUSTRIAL,
            actor=actor,
            query="Write PLC setpoint",
            budget_root_id="root-2",
            read_only=False,
            allowed_tools=(),
        )

    meta = VerifiedResponseMeta(
        verdict=VerdictState.VERIFIED,
        lane=Lane.MIXED,
        domain_profile="mixed_industrial_web",
        airlock_provenance=AirlockProvenance(
            plant_sources=("SCADA TT-402B",),
            web_sources=("https://oem.example.com/ds.pdf",),
            airlock_audit_id="air_123",
            projected_fields={"model": "Rosemount 3144P"},
        ),
    )
    assert meta.verdict == VerdictState.VERIFIED
    assert meta.airlock_provenance is not None


@pytest.mark.n1
async def test_policy_gateway_fail_closed_permits_acl_and_length_only_secrets() -> None:
    audit_events: list[dict[str, Any]] = []
    receipts: list[tuple[str, str, str, dict[str, Any]]] = []

    def _audit(ev: dict[str, Any]) -> str:
        audit_events.append(ev)
        return f"aud_{len(audit_events)}"

    def _receipt(run_id: str, step_id: str, idem: str, payload: dict[str, Any]) -> bool:
        receipts.append((run_id, step_id, idem, payload))
        return True

    # 1. Missing policy -> fail closed
    empty_gw = PolicyGateway(None, audit_sink=_audit)
    dec_missing = empty_gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.read",
            action_kind="read",
        )
    )
    assert not dec_missing.allowed
    assert dec_missing.reason == "missing_policy"

    # 2. Broken regex rule -> fail closed
    broken_gw = PolicyGateway(
        PolicySet(
            policy_version="1.0",
            rules=(
                PolicyRule(
                    rule_id="bad-regex",
                    effect="allow",
                    action_pattern="[unclosed(",
                ),
            ),
        ),
        audit_sink=_audit,
    )
    dec_broken = broken_gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.read",
            action_kind="read",
        )
    )
    assert not dec_broken.allowed
    assert dec_broken.reason.startswith("broken_policy_rule:")

    # 3. Failing audit sink -> fail closed even when rule allows
    def _failing_audit(_ev: dict[str, Any]) -> str:
        raise RuntimeError("audit disk full")

    policy = PolicySet(
        policy_version="2.0",
        rules=(
            PolicyRule(
                rule_id="allow-all-write",
                effect="allow",
                action_pattern=r".*",
                lanes=(Lane.GENERAL,),
                max_risk="write",
            ),
        ),
        document_acls={
            "doc-restricted": {"role:operator": "allow", "u1": "deny"},
        },
    )
    gw_bad_audit = PolicyGateway(policy, audit_sink=_failing_audit)
    dec_bad_audit = gw_bad_audit.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.read",
            action_kind="read",
        )
    )
    assert not dec_bad_audit.allowed
    assert dec_bad_audit.audit_recorded is False
    assert "audit_record_failed" in dec_bad_audit.reason

    # 4. Main PolicyGateway tests
    gw = PolicyGateway(policy, audit_sink=_audit, receipt_sink=_receipt)

    # Document ACL deny wins
    dec_doc_deny = gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.read",
            action_kind="read",
            resource_id="doc-restricted",
        )
    )
    assert not dec_doc_deny.allowed
    assert dec_doc_deny.reason == "document_acl_deny"

    # Unknown MCP tool defaults to write -> blocked in industrial lane
    dec_mcp = gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.INDUSTRIAL,
            tool_id="mcp.mystery_tool",
            action_kind="read",
            is_mcp_tool=True,
            mcp_known_read_only=False,
        )
    )
    assert not dec_mcp.allowed
    assert dec_mcp.effective_action_kind == "write"

    # safety_floor blocks destructive ops and unparseable shell syntax even when allow rule exists
    assert safety_floor("bash", {"command": "rm -rf /"}) is not None
    assert safety_floor("bash", {"command": "echo $(cat /etc/shadow)"}) is not None
    assert safety_floor("bash", {"command": "echo `id`"}) is not None
    assert safety_floor("bash", {"command": "echo 'unterminated"}) is not None
    assert safety_floor("bash", {"command": "ls -la /tmp"}) is None

    dec_sf = gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="bash",
            action_kind="write",
            arguments={"command": "rm -rf /"},
        )
    )
    assert not dec_sf.allowed
    assert dec_sf.safety_violation is not None

    # Single-use exact-arg permit + takeover invalidation
    permit = gw.issue_permit(
        tool_id="files.write",
        arguments={"path": "report.md", "api_key": "SuperSecret-9988!"},
        actor_id="u1",
        session_key="sess-1",
    )
    # Tampered args fail hash check
    dec_tamper = gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.write",
            action_kind="write",
            arguments={"path": "other.md", "api_key": "SuperSecret-9988!"},
            session_id="sess-1",
            permit_token=permit.permit_id,
        )
    )
    assert not dec_tamper.allowed
    assert dec_tamper.reason == "permit_canonical_args_hash_mismatch"

    # Exact args succeed once via execute_gated
    called: list[str] = []

    async def _act() -> str:
        called.append("ran")
        return "ok"

    dec_ok, res = await gw.execute_gated(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.write",
            action_kind="write",
            arguments={"path": "report.md", "api_key": "SuperSecret-9988!"},
            session_id="sess-1",
            run_id="run-1",
            step_id="step-1",
            permit_token=permit.permit_id,
        ),
        _act,
        require_receipt=True,
    )
    assert dec_ok.allowed is True
    assert dec_ok.audit_recorded is True
    assert dec_ok.receipt_recorded is True
    assert res == "ok"
    assert called == ["ran"]
    assert len(receipts) == 1

    # Replay of consumed permit is rejected
    dec_replay, res_replay = await gw.execute_gated(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.write",
            action_kind="write",
            arguments={"path": "report.md", "api_key": "SuperSecret-9988!"},
            session_id="sess-1",
            permit_token=permit.permit_id,
        ),
        _act,
    )
    assert not dec_replay.allowed
    assert dec_replay.reason == "permit_already_consumed"
    assert res_replay is None

    # Takeover invalidates fresh unconsumed permits
    permit2 = gw.issue_permit(
        tool_id="files.write",
        arguments={"path": "b.md"},
        actor_id="u1",
        session_key="sess-1",
    )
    gw.invalidate_takeover("sess-1")
    dec_takeover = gw.evaluate_and_record(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="files.write",
            action_kind="write",
            arguments={"path": "b.md"},
            session_id="sess-1",
            permit_token=permit2.permit_id,
        )
    )
    assert not dec_takeover.allowed
    assert dec_takeover.reason == "permit_not_found_or_invalidated"

    # Length/hash-only secret audit verification
    dumped_audits = json.dumps(audit_events)
    assert "SuperSecret-9988!" not in dumped_audits
    sanitized = sanitize_audit_arguments({"api_key": "SuperSecret-9988!", "path": "x.txt"})
    assert sanitized["api_key"]["redacted"] is True
    assert sanitized["api_key"]["length"] == len("SuperSecret-9988!")
    assert len(sanitized["api_key"]["sha256_prefix"]) == 8


@pytest.mark.n1
async def test_lane_router_lexical_clarification_and_stage2() -> None:
    cfg = _sample_facility()
    router = LaneRouter()

    # General chat
    d_gen = await router.route("Hello, please summarize my notes", facility_config=cfg)
    assert d_gen.lane == Lane.GENERAL
    assert not d_gen.needs_clarification

    # Excel office
    d_xl = await router.route("Crear presupuesto en Excel con márgenes", facility_config=cfg)
    assert d_xl.lane == Lane.GENERAL
    assert "spreadsheet" in d_xl.required_verifiers

    # Industrial SCADA
    d_ind = await router.route("Revisar alarmas SCADA de Bomba 34 en area-1", facility_config=cfg)
    assert d_ind.lane == Lane.INDUSTRIAL
    assert not d_ind.needs_clarification

    # Ambiguous multi-area Bomba 34 without area -> needs_clarification
    d_ambig = await router.route("Revisar alarmas de Bomba 34", facility_config=cfg)
    assert d_ambig.needs_clarification is True
    assert d_ambig.verdict_override == VerdictState.NEEDS_CLARIFICATION
    assert len(d_ambig.clarification_candidates) == 2
    assert d_ambig.general_fallback_available is True

    # Mixed lane
    d_mix = await router.route(
        "Verificar TT-402B en SCADA y buscar reemplazo web datasheet OEM",
        facility_config=cfg,
    )
    assert d_mix.lane == Lane.MIXED
    assert "industrial_reconciler" in d_mix.required_verifiers
    assert "airlock" in d_mix.required_verifiers
    assert "web_citation" in d_mix.required_verifiers

    # Stage 2 low-confidence and timeout
    class _LowConfClassifier:
        async def classify(
            self, query: str, context: dict[str, Any]
        ) -> tuple[Lane, str, float, tuple[str, ...]]:
            del query, context
            return Lane.INDUSTRIAL, "industrial_ot", 0.55, ("industrial_reconciler",)

    low_router = LaneRouter(classifier=_LowConfClassifier(), confidence_threshold=0.70)
    d_low = await low_router.route("Check the unit behavior please")
    assert d_low.needs_clarification is True
    assert d_low.verdict_override == VerdictState.NEEDS_CLARIFICATION

    class _SlowClassifier:
        async def classify(
            self, query: str, context: dict[str, Any]
        ) -> tuple[Lane, str, float, tuple[str, ...]]:
            del query, context
            await asyncio.sleep(0.5)
            return Lane.GENERAL, "general_office", 0.99, ()

    slow_router = LaneRouter(classifier=_SlowClassifier(), stage2_timeout_s=0.05)
    d_slow = await slow_router.route("Ambiguous message needing classifier")
    assert d_slow.needs_clarification is True


@pytest.mark.n1
def test_evidence_airlock_strips_internal_plant_data_and_audits() -> None:
    audits: list[dict[str, Any]] = []

    def _airlock_audit(ev: dict[str, Any]) -> str:
        audits.append(ev)
        return str(ev["audit_id"])

    airlock = EvidenceAirlock(audit_sink=_airlock_audit)

    raw_industrial = {
        "asset_id": "TT-402B",
        "tag": "TT-402B",
        "area": "area-1",
        "linea": "Línea 3",
        "ip": "192.168.10.45",
        "work_order": "WO-2026500",
        "cost": 1450.0,
        "api_key": "sk-secret-plant-token-9999",
        "manufacturer": "Emerson",
        "model": "Rosemount 3144P (tag TT-402B on Línea 3 at 192.168.10.45)",
        "device_category": "Temperature Transmitter",
        "sensor_type": "Pt100 RTD",
        "output_signal": "4-20 mA / HART",
        "process_range": "-200 to 850 C",
        "specs": {
            "accuracy": "±0.1 °C",
            "internal_host": "historian.plant.local",
        },
    }

    res = airlock.project(
        raw_industrial,
        blocked_identifiers=("SCADA-TT402B", "Bomba 34"),
        task_id="task-mix-1",
    )
    dumped = json.dumps(res.spec.model_dump(mode="json"))
    assert "TT-402B" not in dumped
    assert "192.168.10.45" not in dumped
    assert "WO-2026500" not in dumped
    assert "Línea 3" not in dumped
    assert "sk-secret-plant-token-9999" not in dumped
    assert "Emerson" in dumped
    assert "4-20 mA / HART" in dumped
    assert res.spec.public_attributes == {"accuracy": "±0.1 °C"}
    assert "asset_id" in res.stripped_fields
    assert "work_order" in res.stripped_fields
    assert len(audits) == 1

    prov = build_airlock_provenance(
        plant_facts=("SCADA lectura estable",),
        web_facts=("OEM datasheet Emerson",),
        airlock_audit_id=res.audit_id,
        projected_spec=res.spec,
    )
    assert prov.plant_sources == ("SCADA lectura estable",)
    assert prov.web_sources == ("OEM datasheet Emerson",)

    # Fail closed if audit sink fails
    def _raise_audit(_ev: dict[str, Any]) -> str:
        raise RuntimeError("io")

    bad_airlock = EvidenceAirlock(audit_sink=_raise_audit)
    with pytest.raises(AirlockBlockedError):
        bad_airlock.project({"manufacturer": "Emerson", "model": "3144P"})


@pytest.mark.n1
def test_office_excel_builder_and_spreadsheet_verifier_all_checks(tmp_path: Path) -> None:
    builder = OfficeExcelBuilder()
    verifier = SpreadsheetVerifier()

    # 1. Valid workbook with SUM, SUMIFS, AVERAGE, IF, margin arithmetic
    valid_path = tmp_path / "budget_ok.xlsx"
    sheet = ExcelSheetSpec(
        name="Budget",
        headers=("Item", "Category", "Revenue", "Cost", "Margin"),
        rows=(
            ("Pump A", "OT", 1000, 600, None),
            ("Valve B", "OT", 500, 300, None),
            ("Cable C", "IT", 200, 100, None),
        ),
        currency_columns={3: "USD", 4: "USD"},
        formula_cells=(
            ExcelCellSpec(row=2, col=5, formula="=(C2-D2)/C2"),
            ExcelCellSpec(row=3, col=5, formula="=(C3-D3)/C3"),
            ExcelCellSpec(row=4, col=5, formula="=(C4-D4)/C4"),
            ExcelCellSpec(row=5, col=3, formula="=SUM(C2:C4)", currency="USD"),
            ExcelCellSpec(row=5, col=4, formula="=SUM(D2:D4)", currency="USD"),
            ExcelCellSpec(row=6, col=3, formula='=SUMIFS(C2:C4, B2:B4, "OT")', currency="USD"),
            ExcelCellSpec(row=7, col=3, formula="=AVERAGE(C2:C4)"),
            ExcelCellSpec(row=8, col=3, formula='=IF(C5>1000, "OK", "LOW")'),
        ),
    )
    build_res = builder.build_workbook([sheet], valid_path)
    assert build_res.formula_count == 8
    assert valid_path.is_file()

    parsed = read_workbook_ooxml(valid_path)
    assert parsed[0].cells["C5"].formula == "SUM(C2:C4)"

    report = verifier.verify(valid_path, expected_totals={"Budget!C5": 1700.0, "Budget!C6": 1500.0})
    assert report.passed is True
    assert report.verdict == VerdictState.VERIFIED
    assert report.formulas_total == 8
    assert report.formulas_ok == 8
    assert report.badge == "Fórmulas recalculadas: 8/8 OK"
    assert abs(float(report.evaluated_values["Budget!E2"]) - 0.4) < 1e-6

    # 2. Formula errors (#DIV/0! and #NAME?)
    err_path = tmp_path / "errors.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="Errors",
                headers=("A", "B"),
                rows=((10, 0),),
                formula_cells=(
                    ExcelCellSpec(row=3, col=1, formula="=A2/B2"),
                    ExcelCellSpec(row=4, col=1, formula="=BOGUSFUNC(A2)"),
                ),
            )
        ],
        err_path,
    )
    err_report = verifier.verify(err_path)
    assert err_report.passed is False
    assert err_report.verdict == VerdictState.CONTRADICTED
    assert any("#DIV/0!" in e for e in err_report.errors)
    assert any("#NAME?" in e for e in err_report.errors)

    # 3. Mixed currencies in summed range
    mixed_path = tmp_path / "mixed_currency.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="Costs",
                headers=("Item", "Price"),
                rows=(("X", 100),),
                extra_cells=(
                    ExcelCellSpec(row=2, col=2, value=100, currency="USD"),
                    ExcelCellSpec(row=3, col=2, value=200, currency="EUR"),
                ),
                formula_cells=(ExcelCellSpec(row=4, col=2, formula="=SUM(B2:B3)"),),
            )
        ],
        mixed_path,
    )
    mixed_report = verifier.verify(mixed_path)
    assert mixed_report.passed is False
    assert mixed_report.mixed_currencies_detected is True
    assert mixed_report.verdict == VerdictState.CONTRADICTED


@pytest.mark.n1
async def test_web_search_egress_guard_and_web_citation_verifier() -> None:
    guard = EgressGuard(allowed_domains=("emerson.com",))
    assert guard.validate_url("https://www.emerson.com/en-us/rosemount-3144p")
    with pytest.raises(EgressBlockedError):
        guard.validate_url("file:///etc/passwd")
    with pytest.raises(EgressBlockedError):
        guard.validate_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(EgressBlockedError):
        guard.validate_url("https://evil.example.org/phish")

    # Fetcher with MockTransport + redirect block check
    def _mock_handler(request: httpx.Request) -> httpx.Response:
        if "redirect" in str(request.url):
            return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})
        html = """
        <html><head><title>Emerson Rosemount 3144P Datasheet</title></head>
        <body>
          <table>
            <tr><th>Output Signal</th><td>4-20 mA / HART</td></tr>
            <tr><th>Status</th><td>Discontinued</td></tr>
          </table>
        </body></html>
        """
        return httpx.Response(200, text=html)

    fetcher = HttpWebFetcher(
        egress_guard=EgressGuard(),
        transport=httpx.MockTransport(_mock_handler),
        oem_domains=("emerson.com",),
    )
    page = await fetcher.fetch("https://www.emerson.com/rosemount-3144p")
    assert page.provenance == "untrusted"
    assert page.is_primary_oem is True
    assert page.extracted_specs["output signal"] == "4-20 mA / HART"

    with pytest.raises(EgressBlockedError):
        await fetcher.fetch("https://www.emerson.com/redirect")

    # WebCitationVerifier: verified core specs + explicit not_documented for missing price
    verifier = WebCitationVerifier()
    rep_ok = verifier.verify(
        manufacturer="Emerson",
        model="Rosemount 3144P",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="output_signal",
                value="4-20 mA / HART",
                source_url="https://www.emerson.com/rosemount-3144p",
            ),
        ),
        fetched_pages=(page,),
        required_attributes=("output_signal", "price"),
    )
    assert rep_ok.passed is True
    assert rep_ok.verdict == VerdictState.VERIFIED
    assert rep_ok.documented_fields["price"] == "not_documented"
    assert "price" in rep_ok.not_documented_fields

    # Fabricated unconsulted URL must fail closed
    rep_fab = verifier.verify(
        manufacturer="Emerson",
        model="Rosemount 3144P",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="price",
                value="$999",
                source_url="https://fake-vendor.example.com/price",
            ),
        ),
        fetched_pages=(page,),
    )
    assert rep_fab.passed is False
    assert rep_fab.verdict == VerdictState.CONTRADICTED
    assert "https://fake-vendor.example.com/price" in rep_fab.unverified_urls

    # Pure missing attributes -> NOT_DOCUMENTED
    empty_page = WebPageExtract(
        url="https://www.emerson.com/legacy",
        final_url="https://www.emerson.com/legacy",
        status_code=200,
        title="Legacy",
        text_excerpt="Legacy archive page",
        is_primary_oem=True,
    )
    rep_nd = verifier.verify(
        manufacturer="Emerson",
        model="Legacy-X",
        citation_date="2026-11-26",
        claimed_fields=(),
        fetched_pages=(empty_page,),
        required_attributes=("price",),
    )
    assert rep_nd.verdict == VerdictState.NOT_DOCUMENTED


@pytest.mark.n1
def test_industrial_verifiers_units_asset_resolver_health_freshness_reconciler() -> None:
    cfg = _sample_facility()
    ref_time = datetime(2026, 11, 26, 14, 30, tzinfo=UTC)

    # 1. Unit conversions
    bar_val, bar_u = normalize_unit_and_value(14.50377377, "psi", "bar")
    assert abs(bar_val - 1.0) < 1e-5 and bar_u == "bar"
    c_val, c_u = normalize_unit_and_value(212.0, "°F", "°C")
    assert abs(c_val - 100.0) < 1e-5 and c_u == "C"
    with pytest.raises(ValueError):
        normalize_unit_and_value(10.0, "psi", "C")

    # 2. AssetResolver top-3 nearest on unknown tag TT-999Z
    resolver = AssetResolver()
    res_nf = resolver.resolve(cfg, "TT-999Z")
    assert res_nf.status == "not_found"
    assert res_nf.verdict == VerdictState.ASSET_NOT_FOUND
    assert len(res_nf.nearest_assets) == 3
    assert res_nf.nearest_assets[0].asset_id == "tt-402b"

    # 3. HealthGuard HTTP 503 degraded banner HH:MM
    health = HealthGuard().evaluate_sources(
        {"cmms": "HTTP 503 Service Unavailable"},
        down_since_by_source={"cmms": datetime(2026, 11, 26, 14, 20, tzinfo=UTC)},
        available_sources=("scada",),
        reference_time=ref_time,
    )
    assert health.degraded is True
    assert health.verdict == VerdictState.PARTIAL_EVIDENCE
    assert health.down_since["cmms"] == "14:20"
    assert "14:20" in (health.degraded_banner or "")
    assert "SCADA" in (health.degraded_banner or "")

    # 4. FreshnessPolicy 19h vs 15min TTL
    stale_obs = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="pump-34-a1",
        observed_label="Bomba 34",
        value=3.4,
        unit="bar",
        area="area-1",
        source_time=ref_time - timedelta(hours=19),
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading"},
    )
    fr = FreshnessPolicy().check_freshness(
        stale_obs, max_ttl_seconds=900.0, reference_time=ref_time
    )
    assert fr.is_stale is True
    assert fr.verdict == VerdictState.STALE_DATA
    assert fr.allow_as_current_reading is False
    assert "19 h" in fr.message and "15 min" in fr.message
    assert fr.refresh_action == "refresh_live_source"

    # 5. IndustrialReconciler: unit-equivalent agreement vs divergent contradiction
    reconciler = IndustrialReconciler()
    task = TaskSpec(
        task_id="t-rec-1",
        user_id="op-1",
        profile_id="p-1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Compare Bomba 34 pressure",
        evidence_requirements=EvidenceRequirements(min_sources=1, max_staleness_seconds=3600.0),
    )

    obs_scada = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="SCADA-P34-A1",
        observed_label="Bomba 34",
        value=3.4,
        unit="bar",
        area="area-1",
        source_time=ref_time - timedelta(minutes=2),
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-1"},
    )
    obs_hmi_agree = Observation(
        source="historian",
        session_id="sess-2",
        asset_id="pump-34-a1",
        observed_label="Bomba 34",
        value=49.31,
        unit="psi",
        area="area-1",
        source_time=ref_time - timedelta(minutes=3),
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-2"},
    )
    rec_agree = reconciler.reconcile(
        task=task,
        config=cfg,
        observations=(obs_scada, obs_hmi_agree),
        target_asset_query="Bomba 34",
        target_area="area-1",
        reference_time=ref_time,
    )
    assert rec_agree.verdict == VerdictState.VERIFIED
    assert any("Acuerdo numérico" in a for a in rec_agree.agreements)
    assert not rec_agree.contradictions

    obs_hmi_conflict = obs_hmi_agree.model_copy(update={"value": 75.0})
    rec_conflict = reconciler.reconcile(
        task=task,
        config=cfg,
        observations=(obs_scada, obs_hmi_conflict),
        target_asset_query="Bomba 34",
        target_area="area-1",
        reference_time=ref_time,
    )
    assert rec_conflict.verdict == VerdictState.CONTRADICTED
    assert len(rec_conflict.contradictions) >= 1


@pytest.mark.n1
async def test_router_no_hardcoded_bomba_ui_general_bypass_and_multi_area_ambiguity() -> None:
    for engine_file in Path("src/engine").glob("*.py"):
        txt = engine_file.read_text(encoding="utf-8").lower()
        assert "bomba" not in txt
        assert "sc-77" not in txt
        assert "cmms-77" not in txt
        assert "facility-b" not in txt

    cfg = _sample_facility()
    router = LaneRouter()

    # ui_lane=Lane.GENERAL must short-circuit BEFORE plant multi-asset disambiguation
    d_gen = await router.route("Check Bomba 34", ui_lane=Lane.GENERAL, facility_config=cfg)
    assert d_gen.lane == Lane.GENERAL
    assert d_gen.needs_clarification is False
    assert d_gen.stage_used == "explicit_ui"

    # Multi-area query must trigger needs_clarification instead of silently picking area-1
    d_multi_area = await router.route(
        "Comparar Bomba 34 en area-1 con Bomba 34 en area-2",
        facility_config=cfg,
    )
    assert d_multi_area.needs_clarification is True
    assert d_multi_area.verdict_override == VerdictState.NEEDS_CLARIFICATION
    assert len(d_multi_area.clarification_candidates) == 2

    # Multi-area query even with unknown assets triggers clarification
    d_multi_area_generic = await router.route(
        "Comparar presion en area-1 con presion en area-2",
        facility_config=cfg,
    )
    assert d_multi_area_generic.needs_clarification is True
    assert d_multi_area_generic.verdict_override == VerdictState.NEEDS_CLARIFICATION


@pytest.mark.n1
def test_safety_floor_apostrophe_prompts_and_all_challenger_bypasses() -> None:
    # Benign natural-language prompts with apostrophes under "prompt" must pass
    assert safety_floor("turn.prompt", {"prompt": "What's the temperature of Pump 34?"}) is None
    assert safety_floor("turn.prompt", {"prompt": "Don't restart line 2 yet"}) is None
    assert safety_floor("turn.prompt", {"prompt": "I'm checking if it's calibrated"}) is None

    # All Challenger bypass variants MUST be blocked
    bypass_payloads = [
        "rm --recursive --force /",
        "rm -rf -- /",
        "rm -rf /etc/passwd",
        "rm -rf /home/user",
        "rm -r -f /etc/shadow",
        'python3 -c "rm -rf /"',
        'python3 -c "import os; os.system(\'rm -rf /\')"',
        "/bin/rm -rf /",
        r"r\m -rf /",
        '""rm -rf /',
        "rm${IFS}-rf${IFS}/",
        "chmod -R 777 /etc",
        "chmod --recursive a+rwx /home/user",
        "cat <(cat /etc/shadow)",
        "echo $(id",
        "rm -rf //",
        "rm -rf /./",
        "rm -rf /tmp/../../",
        "rm -rf /tmp/../",
        "sudo -u root rm -v -r -f /",
        "env -u PATH rm -v -r -f /",
        "nice -n 10 sudo -u root rm -v -r -f //",
        'bash -c \'python3 -c "import os; os.system(\\"rm -rf /\\")"\'',
        'python3 -c "import shutil; shutil.rmtree(\'/\')"',
        'python3 -c "from shutil import rmtree as rt; rt(\'/etc\')"',
        'python3 -c "import shutil; shutil.rmtree(\'/tmp/../../\')"',
        "sudo -Eu root rm -v -r -f //",
        "env -iu PATH rm -v -r -f //",
        "sudo -nu root rm -v -r -f /./",
        'python3 -c "import shutil; fn = shutil.rmtree; fn(\'/\')"',
        'python3 -c "import shutil; p = \'/\'; shutil.rmtree(p)"',
        'python3 -c "from pathlib import Path; import shutil; '
        'p = Path(\'/etc\'); shutil.rmtree(p)"',
        'python3 -c "import subprocess; subprocess.run([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import subprocess; run = subprocess.run; run([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import subprocess; subprocess.Popen([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import subprocess; subprocess.call([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import subprocess; subprocess.check_call([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import subprocess; subprocess.check_output([\'rm\', \'-rf\', \'/\'])"',
        'python3 -c "import os; os.popen(\'rm -rf /\')"',
        "find / -delete",
        "find /etc -delete",
        "sudo -u root find / -delete",
        "find / -exec rm -rf {} +",
        r"find / -exec rm -rf {} \;",
        "find /etc -execdir rm -rf {} +",
        r"find / -ok rm -rf {} \;",
        "find /etc -okdir rm -rf {} +",
        "find /tmp/work -exec rm -rf /etc {} +",
        "echo / | xargs rm -rf",
        "find / -name '*' | xargs rm -rf",
        r"printf '/etc\n' | xargs rm -rf",
        "echo / | sudo -u root xargs -0 -r -n 1 -P 4 -I {} rm -rf {}",
        'python3 -c "import shutil; a, b = \'/\', \'/tmp\'; shutil.rmtree(a)"',
        'python3 -c "import shutil; a, *rest = \'/\', \'/tmp\', \'/var\'; shutil.rmtree(a)"',
        'python3 -c "import shutil; x = \'etc\'; shutil.rmtree(f\'/{x}\')"',
        'python3 -c "import shutil; (fn := shutil.rmtree)(\'/\')"',
        'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; d[\'f\'](\'/\')"',
        'python3 -c "import shutil; d = {\'p\': \'/\'}; shutil.rmtree(d[\'p\'])"',
        r"find / -exec sh -c 'rm -rf {}' \;",
        'find / -exec sh -c \'rm -rf "$1"\' _ {} +',
        'find / -exec sh -c \'rm -rf "$@"\' sh {} +',
        'find / -exec sh -c \'rm -rf "$0"\' {} +',
        "find /tmp / -exec sh -c 'rm -rf {}' +",
        "echo / | xargs sh -c 'rm -rf $1' _",
        'echo / | xargs sh -c \'rm -rf "$0"\'',
        "echo / | xargs sh -c 'rm -rf $@' _",
        'echo / | xargs sh -c \'for p in "$@"; do rm -rf "$p"; done\' _',
        'python3 -c "import shutil; a, *b = \'/tmp\', \'/\'; shutil.rmtree(b[0])"',
        'python3 -c "import shutil; d = {\'a\': {\'p\': \'/\'}}; shutil.rmtree(d[\'a\'][\'p\'])"',
        'python3 -c "import shutil; d = {\'a\': {\'f\': shutil.rmtree}}; d[\'a\'][\'f\'](\'/\')"',
        'find / -exec sh -c \'rm -rf "$@"\' _ /tmp {} +',
        'find /tmp -exec sh -c \'rm -rf "$@"\' _ /etc {} +',
        'find / -exec sh -c \'rm -rf "$@"\' _ /var /tmp {} +',
        "echo / | xargs -I% sh -c 'rm -rf %'",
        "echo / | xargs -I % sh -c 'rm -rf %'",
        "echo / | xargs --replace=% sh -c 'rm -rf %'",
        'echo / | xargs sh -c \'rm -rf "$2"\' _ /tmp/safe',
        r"find / -exec bash -o errexit -c 'rm -rf {}' \;",
        'echo / | xargs bash -o errexit -c \'rm -rf "$1"\' _',
        r"find / -exec sh -c -- 'rm -rf {}' \;",
        "find / -exec sh -c -- 'rm -rf {}' +",
        r"find / -exec bash -ec 'rm -rf {}' \;",
        r"find / -exec bash -ce 'rm -rf {}' \;",
        r"find / -exec bash +o errexit -c 'rm -rf {}' \;",
        'python3 -c "import shutil; fns = [shutil.rmtree]; fns[0](\'/\')"',
        'python3 -c "import shutil; [shutil.rmtree][0](\'/\')"',
        (
            'python3 -c "import shutil; d = {\'a\': [{\'p\': \'/\'}]}; '
            'shutil.rmtree(d[\'a\'][0][\'p\'])"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': {\'p\': \'/\'}}; '
            'shutil.rmtree(d[\'a\'].get(\'p\'))"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': {\'f\': shutil.rmtree}}; '
            'd[\'a\'].get(\'f\')(\'/\')"'
        ),
        'python3 -c "import shutil; getattr(shutil, \'rmtree\')(\'/\')"',
        "echo / | xargs --replace sh -c 'rm -rf {}'",
        "echo / | xargs --replace rm -rf {}",
        "echo / | xargs --eof sh -c 'rm -rf \"$1\"' _",
        "echo / | xargs --eof rm -rf",
        "echo / | xargs --max-lines sh -c 'rm -rf \"$1\"' _",
        "echo / | xargs --max-lines rm -rf",
        "echo / | xargs -e sh -c 'rm -rf \"$1\"' _",
        "echo / | xargs -l sh -c 'rm -rf \"$1\"' _",
        "echo / | xargs -re sh -c 'rm -rf \"$1\"' _",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$1\"' _ /",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$@\"' _ /etc",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$0\"' /",
        "find /tmp/work -exec sh -c 'for p; do rm -rf \"$p\"; done' _ /etc {} +",
        "echo /tmp/work | xargs sh -c 'for p; do rm -rf \"$p\"; done' _ /etc",
        'python3 -c "import shutil; d = {}; p = d.get(\'p\', \'/\'); shutil.rmtree(p)"',
        'python3 -c "import shutil; d = {\'x\': 1}; p = d.get(\'p\', \'/\'); shutil.rmtree(p)"',
        (
            'python3 -c "import shutil; d = {\'a\': {}}; '
            'p = d[\'a\'].get(\'p\', \'/\'); shutil.rmtree(p)"'
        ),
        'python3 -c "import shutil; a = [\'/\']; shutil.rmtree(*a)"',
        'python3 -c "import shutil; kw = {\'path\': \'/\'}; shutil.rmtree(**kw)"',
        'python3 -c "import shutil; d = {}; d[\'p\'] = \'/\'; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; d = {}; d |= {\'p\': \'/\'}; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; a = []; a.append(\'/\'); shutil.rmtree(a[0])"',
        'python3 -c "import shutil; a = []; a.extend([\'/\']); shutil.rmtree(a[0])"',
        'python3 -c "import shutil; f = {}; f[\'r\'] = shutil.rmtree; f[\'r\'](\'/\')"',
        'python3 -c "import shutil; f = []; f.append(shutil.rmtree); f[0](\'/\')"',
        'python3 -c "import shutil, builtins; builtins.getattr(shutil, \'rmtree\')(\'/\')"',
        'python3 -c "import shutil; d = {\'p\': \'/\'}; d2 = d; shutil.rmtree(d2[\'p\'])"',
        (
            'python3 -c "import shutil; fns = {\'r\': shutil.rmtree}; '
            'f2 = fns; f2[\'r\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [{\'p\': \'/\'}]; '
            'b = a; shutil.rmtree(b[0][\'p\'])"'
        ),
        'python3 -c "import shutil; a = [shutil.rmtree]; b = a; b[0](\'/\')"',
        'python3 -c "import shutil; d = dict(p=\'/\'); shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; kw = dict(path=\'/\'); shutil.rmtree(**kw)"',
        (
            'python3 -c "import subprocess; kw = dict(args=[\'rm\', \'-rf\', \'/\']); '
            'subprocess.run(**kw)"'
        ),
        'python3 -c "import shutil; d = {}; d.update(p=\'/\'); shutil.rmtree(d[\'p\'])"',
        (
            'python3 -c "import shutil; f = {}; '
            'f.update(r=shutil.rmtree); f[\'r\'](\'/\')"'
        ),
        'python3 -c "import shutil; a = list((\'/\',)); shutil.rmtree(a[0])"',
        'python3 -c "import shutil; d = {}; d = d | {\'p\': \'/\'}; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; a = [\'/tmp/work\'] + [\'/\']; shutil.rmtree(a[1])"',
        (
            'python3 -c "import shutil; d = {\'a\': []}; '
            'd[\'a\'].append(\'/\'); shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'p = d.setdefault(\'p\', \'/\'); shutil.rmtree(p)"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a.insert(0, \'/\'); shutil.rmtree(a[0])"'
        ),
        "(rm -rf /)",
        "find / -exec sh -c '(rm -rf \"$1\")' _ {} +",
        "echo / | xargs sh -c '(rm -rf \"$1\")' _",
        "find / -exec sh -c '{ rm -rf \"$1\"; }' _ {} +",
        "echo / | xargs sh -c '{ rm -rf \"$1\"; }' _",
        "{ rm -rf /; }",
        'python3 -c "import shutil; d = dict([(\'p\', \'/\')]); shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; f = [None] + [shutil.rmtree]; f[1](\'/\')"',
        (
            'python3 -c "import shutil; pairs = [(\'r\', shutil.rmtree)]; '
            'f = dict(pairs); f[\'r\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; pairs = [(\'r\', shutil.rmtree)]; '
            'f = {}; f.update(pairs); f[\'r\'](\'/\')"'
        ),
        'python3 -c "import shutil; d = {\'p\': \'/\'}; d2 = d.copy(); shutil.rmtree(d2[\'p\'])"',
        'python3 -c "import shutil; f = {\'r\': shutil.rmtree}; f2 = f.copy(); f2[\'r\'](\'/\')"',
        'python3 -c "import shutil; a = [\'/\']; b = a.copy(); shutil.rmtree(b[0])"',
        'python3 -c "import shutil; a = [shutil.rmtree]; b = a.copy(); b[0](\'/\')"',
        'python3 -c "import shutil; d = {\'/\': 1}; a = list(d); shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0].append(shutil.rmtree); a[0][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0].insert(0, shutil.rmtree); a[0][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0].extend([shutil.rmtree]); a[0][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0][0] = shutil.rmtree; a[0][0](\'/\')"'
        ),
        "{ echo /; } | xargs rm -rf",
        "{ echo / ; } | xargs rm -rf",
        "(echo /; echo /tmp) | xargs rm -rf",
        "find / -exec sh -c 'echo ok & rm -rf \"$1\"' _ {} +",
        "echo / | xargs sh -c 'echo ok & rm -rf \"$1\"' _",
        'python3 -c "import shutil; fns = [shutil.rmtree]; a = fns + [\'/\']; shutil.rmtree(a[1])"',
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0] += [shutil.rmtree]; a[0][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/work\']}; '
            'd[\'a\'] += [shutil.rmtree]; d[\'a\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[shutil.rmtree]]; '
            'a[0] += [\'/\']; a[0][0](a[0][1])"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [shutil.rmtree]}; '
            'd[\'a\'] += [\'/\']; d[\'a\'][0](d[\'a\'][1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = fns.copy() + [\'/\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = list(fns) + [\'/\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = [*fns] + [\'/\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = [*fns, \'/\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/\']; '
            'a = paths.copy() + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/\']; '
            'a = list(paths) + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/\']; '
            'a = [*paths] + [shutil.rmtree]; a[1](a[0])"'
        ),
        'python3 -c "import shutil; d = {\'/\': 1}; a = [*d]; shutil.rmtree(a[0])"',
        'python3 -c "import shutil; d = {\'/\': 1}; a = list(d.keys()); shutil.rmtree(a[0])"',
        'python3 -c "import shutil; d = {\'/\': 1}; a = [*d.keys()]; shutil.rmtree(a[0])"',
        "(echo /; echo /tmp) 2>/dev/null | xargs rm -rf",
        "{ echo /; echo /tmp; } 2>/dev/null | xargs rm -rf",
        "{ echo /; echo /tmp; } 2>&1 | xargs rm -rf",
        "(echo /; echo /tmp) >/dev/null 2>&1 | xargs rm -rf",
        "{ echo /; echo /tmp; }>/dev/null | xargs rm -rf",
        # Challenger r11 + Reviewer r11 repros
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).append(shutil.rmtree); d[\'a\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [shutil.rmtree]).append(\'/\'); d[\'a\'][0](d[\'a\'][1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).extend([shutil.rmtree]); d[\'a\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [shutil.rmtree]).extend([\'/\']); d[\'a\'][0](d[\'a\'][1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).insert(0, shutil.rmtree); d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [shutil.rmtree]).insert(0, \'/\'); d[\'a\'][1](d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {}).setdefault(\'b\', [\'/tmp/work\']).append(shutil.rmtree); '
            'd[\'a\'][\'b\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; p = [\'/tmp/work\']; d = {}; '
            'd.setdefault(\'a\', p).append(shutil.rmtree); d[\'a\'][1](\'/\')"'
        ),
        (
            'python3 -c "import os, shutil; d = os.environ.copy(); '
            'd[\'a\'] = [\'/tmp/work\']; d[\'a\'][0] = shutil.rmtree; d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = vars(); '
            'd[\'a\'] = [\'/tmp/work\', \'/\']; d[\'a\'][0] = shutil.rmtree; '
            'd[\'a\'][0](d[\'a\'][1])"'
        ),
        'python3 -c "import shutil; a = [None]; a += [shutil.rmtree, \'/\']; a[1](a[2])"',
        'python3 -c "import shutil; a = [0]; a += [shutil.rmtree, \'/\']; a[1](a[2])"',
        (
            'python3 -c "import shutil; d = {\'a\': [0]}; '
            'd[\'a\'] += [shutil.rmtree, \'/\']; d[\'a\'][1](d[\'a\'][2])"'
        ),
        "(echo /; echo /tmp) 2>| /dev/null | xargs rm -rf",
        "{ echo /; echo /tmp; } 2>| /dev/null | xargs rm -rf",
        "(echo /; echo /tmp) 2>/dev/null \\\n| xargs rm -rf",
        "(echo /; echo /tmp) {fd}>/dev/null | xargs rm -rf",
        "echo / | 2>/dev/null xargs rm -rf",
        "2>/dev/null echo / | xargs rm -rf",
        "(echo /; echo /tmp) 2>/dev/null</dev/null | xargs rm -rf",
        "{ echo /; echo /tmp; } 2>/dev/null</dev/null | xargs rm -rf",
        "(echo /; echo /tmp) 2>/dev/null>/tmp/err_unused | xargs rm -rf",
        'python3 -c "import shutil; fns = [shutil.rmtree]; a = fns[:] + [\'/\']; a[0](a[1])"',
        (
            'python3 -c "import shutil; paths = [\'/\']; '
            'a = paths[:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'/\': shutil.rmtree}; '
            'a = [*d]; b = list(d.values()); b[0](a[0])"'
        ),
        # Challenger r12 + Reviewer r12 repros
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'f\'] = shutil.rmtree; d[\'a\'][\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'p\'] = \'/\'; shutil.rmtree(d[\'a\'][\'p\'])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [None])[0] = shutil.rmtree; d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\'])[0] = \'/\'; shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {\'b\': [\'/tmp/work\']})[\'b\'].append(shutil.rmtree); '
            'd[\'a\'][\'b\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {}).setdefault(\'b\', {})[\'f\'] = shutil.rmtree; '
            'd[\'a\'][\'b\'][\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'b\'] = [\'/tmp/work\']; '
            'd[\'a\'][\'b\'].append(shutil.rmtree); d[\'a\'][\'b\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/work\']}; '
            'd.setdefault(\'a\', [])[0] = shutil.rmtree; d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {\'b\': [\'/tmp/work\']})[\'b\'] += [shutil.rmtree]; '
            'd[\'a\'][\'b\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {\'b\': {}})[\'b\'].update(f=shutil.rmtree); '
            'd[\'a\'][\'b\'][\'f\'](\'/\')"'
        ),
        'python3 -c "import shutil; fns = [shutil.rmtree]; a = fns[0:] + [\'/\']; a[0](a[1])"',
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[0:1] + [\'/\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\', \'/\']; '
            'a = paths[1:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\', \'/\']; '
            'a = paths[-1:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/\', \'/tmp/work\']; '
            'a = paths[::-1] + [shutil.rmtree]; a[2](a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[::2] + [\'/\']; a[0](a[1])"'
        ),
        "echo / | env 2>/dev/null xargs rm -rf",
        "echo / | env FOO=1 2>/dev/null xargs rm -rf",
        "echo / | nice 2>/dev/null xargs rm -rf",
        "find / -maxdepth 0 -exec env 2>/dev/null rm -rf {} +",
        "(echo /; echo /tmp) 2>/dev/null |\nxargs rm -rf",
        "echo / |\nxargs rm -rf",
        "(echo /; echo /tmp) 2>/dev/null |&\nxargs rm -rf",
        # Challenger r13 + Reviewer r13 repros
        "echo / |\\\nxargs rm -rf",
        "echo / | \\\nxargs rm -rf",
        "echo / |\t\\\n\txargs rm -rf",
        "echo / | \\\n xargs rm -rf",
        "echo / | \\\nsh -c 'rm -rf \"$1\"' _",
        "echo / | env \\\n xargs rm -rf",
        "find / -maxdepth 0 -exec \\\nrm -rf {} +",
        "find / -maxdepth 0 -exec \\\n rm -rf {} +",
        "echo / | # comment\nxargs rm -rf",
        "echo / |&\n# comment\nxargs rm -rf",
        "echo / |\n# c\nxargs rm -rf",
        "echo / |\\\n# comment\nxargs rm -rf",
        "bash -c $'echo / |\\nxargs rm -rf'",
        "bash -c $'echo / |\\nxargs sh -c \\'rm -rf \"$1\"\\' _'",
        "sh -c $'rm\\x20-rf\\x20/'",
        "echo / | xargs 2>/dev/null -I {} rm -rf {}",
        "echo / | xargs 2>/dev/null -n 1 sh -c 'rm -rf \"$1\"' _",
        "echo / | env 2>/dev/null xargs 2>/dev/null -n 1 rm -rf",
        "find 2>/dev/null -L / -maxdepth 0 -delete",
        "find 2>/dev/null -H / -maxdepth 0 -exec rm -rf {} +",
        "echo / | env>/dev/null xargs rm -rf",
        "echo / | xargs>/dev/null rm -rf",
        "find / -maxdepth 0 -exec env>/dev/null rm -rf {} +",
        "rm>/dev/null -rf /",
        "find>/dev/null / -maxdepth 0 -exec rm -rf {} +",
        "env>/dev/null rm -v -r -f /",
        "echo / | xargs {fd}>/dev/null -I {} rm -rf {}",
        "find / -maxdepth 0 -exec rm>/dev/null -rf {} +",
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[0:1:None] + [\'/\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[None:1] + [\'/\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\', \'/\']; '
            'a = paths[1:None] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[None:None:None] + [\'/\']; a[0](a[2])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [len])[0:1] = [shutil.rmtree]; d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [len]; '
            'a[0:1] = [shutil.rmtree]; a[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\'])[0:1] = [\'/\']; '
            'shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a[0:1] = [\'/\']; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [len]; '
            'a[0:1] = [len, shutil.rmtree]; a[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [len, len, len]; '
            'a[0:2] = [shutil.rmtree]; a[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [shutil.rmtree]; '
            'a[1:1] = [\'/\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; a = [len, len]; '
            'a[::-1] = [len, shutil.rmtree]; a[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [[len]])[0][0:1] = [shutil.rmtree]; d[\'a\'][0][0](\'/\')"'
        ),
        # Challenger r14 repros + symmetric variants
        'bash -c "echo / | \\$\'xargs\' rm -rf"',
        'bash -c "\\$\'rm\' -rf /"',
        'bash -c "\\$\'r\'m -rf /"',
        'bash -c "find / -maxdepth 0 -exec \\$\'rm\' -rf {} +"',
        'bash -c "echo / | env \\$\'xargs\' rm -rf"',
        'bash -c "echo / | xargs -I {} \\$\'rm\' -rf {}"',
        'bash -c "(echo / | \\$\'xargs\' rm -rf)"',
        'bash -c "echo / | # c\n\\$\'xargs\' rm -rf"',
        'bash -c "sh -c \\"echo / | \\\\\\$\'xargs\' rm -rf\\""',
        'bash -c "echo / | \\$\'\\x78args\' rm -rf"',
        "echo / | $\\\n'xargs' rm -rf",
        "rm -rf $\\\n'/'",
        "find / -maxdepth 0 -exec $\\\n'rm' -rf {} +",
        "echo / | $\\\n\\\n'xargs' rm -rf",
        'bash -c "echo / | \\$\\\n\'xargs\' rm -rf"',
        "echo / | # c\n$\\\n'xargs' rm -rf",
        'python3 -c "import shutil; a = [\'/tmp/work\']; a[0:1] = \'/\'; shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'p = \'/\'; a[0:1] = p; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a[0:1] = {\'/\': 1}; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'd = {\'/\': 1}; a[0:1] = d; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\'])[0:1] = \'/\'; shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\'])[0:1] = {\'/\': 1}; shutil.rmtree(d[\'a\'][0])"'
        ),
        'python3 -c "import shutil; a = [len]; a[0:1] += [shutil.rmtree]; a[1](\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a[0:1] += \'/\'; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [len])[0:1] += [shutil.rmtree]; d[\'a\'][1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'del a[0]; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'del a[0:1]; shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; a = [len, shutil.rmtree]; del a[0]; a[0](\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'a.pop(0); shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; a = [len, shutil.rmtree]; a.pop(0); a[0](\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'p = a.pop(); shutil.rmtree(p)"'
        ),
        'python3 -c "import shutil; a = [len, shutil.rmtree]; f = a.pop(); f(\'/\')"',
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [len, shutil.rmtree]).pop(0); d[\'a\'][0](\'/\')"'
        ),
        'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; f = d.pop(\'f\'); f(\'/\')"',
        'python3 -c "import shutil; a = [[\'/\']]; shutil.rmtree(a.pop()[0])"',
        'python3 -c "import shutil; d = {\'a\': [shutil.rmtree]}; d.pop(\'a\')[0](\'/\')"',
        'python3 -c "import shutil; d = {}; shutil.rmtree(d.pop(\'missing\', \'/\'))"',
        # Challenger r15 repros (33) + symmetric variants
        '$"rm" -rf /',
        '$"r"m -rf /',
        'rm -rf $"/"',
        'echo / | $"xargs" -I {} rm -rf {}',
        'echo / | env $"xargs" -I {} rm -rf {}',
        'echo / | $""xargs -I {} rm -rf {}',
        'find / -maxdepth 0 -exec $"rm" -rf {} +',
        'bash -c \'echo / | $"xargs" -I {} rm -rf {}\'',
        'bash -c "echo / | \\$\\"xargs\\" -I {} rm -rf {}"',
        'echo / | $\\\n"xargs" -I {} rm -rf {}',
        'bash -c $\'echo / | $"xargs" -I {} rm -rf {}\'',
        '$"bash" -c \'echo / | $"xargs" -I {} rm -rf {}\'',
        '$"sh" -c "echo / | \\$\\"xargs\\" -I {} rm -rf {}"',
        'echo / | $"x"$"a"rgs -I {} rm -rf {}',
        'bash -c "echo / | \\$\\\n\\"xargs\\" -I {} rm -rf {}"',
        '$"python3" -c "import shutil; shutil.rmtree(\'/\')"',
        'python3 -c $"import shutil; shutil.rmtree(\'/\')"',
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/x\', \'/tmp/y\']}; '
            'a = [*d.pop(\'a\'), shutil.rmtree]; a[2](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/x\', \'/tmp/y\']]; '
            'b = [*a.pop(0), shutil.rmtree]; b[2](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/x\', \'/tmp/y\']}; '
            'a = d.pop(\'a\') + [shutil.rmtree]; a[2](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/x\', \'/tmp/y\']]; '
            'b = a.pop(0) + [shutil.rmtree]; b[2](\'/\')"'
        ),
        (
            'python3 -c "import shutil; k = [\'f\']; d = {\'f\': shutil.rmtree}; '
            'd[k.pop(0)](\'/\')"'
        ),
        (
            'python3 -c "import shutil; k = [\'f\']; d = {\'f\': shutil.rmtree}; '
            'd.get(k.pop(0))(\'/\')"'
        ),
        'python3 -c "import shutil; k = [\'f\']; {k.pop(0): shutil.rmtree}[\'f\'](\'/\')"',
        (
            'python3 -c "import shutil; k = [\'f\']; '
            'dict([(k.pop(0), shutil.rmtree)])[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; k = [\'a\']; d = {}; '
            'd[k.pop(0)] = \'/\'; shutil.rmtree(d[\'a\'])"'
        ),
        (
            'python3 -c "import shutil; k = [\'f\']; d = {}; '
            'd[k.pop(0)] = shutil.rmtree; d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; k = [\'a\']; d = {}; '
            'd.setdefault(k.pop(0), [\'/\']); shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; k = [\'a\']; d = {\'a\': [\'/tmp/work\', \'/\']}; '
            'del d[k.pop(0)][0]; shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; k = [\'f\']; d = {}; '
            'd.update([(k.pop(0), shutil.rmtree)]); d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; k = [\'a\']; d = {}; '
            'd.setdefault(k.pop(0), [shutil.rmtree]); d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; src = [{\'f\': shutil.rmtree}]; '
            'd = {}; d.update(src.pop(0)); d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; src = [shutil.rmtree]; '
            'd = {}; d.update(f=src.pop(0)); d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; src = [[(\'f\', shutil.rmtree)]]; '
            'dict(src.pop(0))[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [len, shutil.rmtree]; '
            'x, y = str(a.pop(0)), a[0]; y(\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [len(a.pop(0)), a[0]]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; a = [\'x\', shutil.rmtree]; '
            'b = [len(a.pop(0)), a[0]]; b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; idx = [0]; a = [\'/tmp/work\', \'/\']; '
            'del a[idx.pop()]; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; idx = [0]; a = [len, shutil.rmtree]; '
            'del a[idx.pop()]; a[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; idx = [0]; d = {\'a\': [\'/tmp/work\', \'/\']}; '
            'del d[\'a\'][idx.pop()]; shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = (len(a.pop(0)), a[0]); shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'd = {\'x\': len(a.pop(0)), \'y\': a[0]}; shutil.rmtree(d[\'y\'])"'
        ),
        'python3 -c "import shutil; p = \'\'; p += \'/\'; shutil.rmtree(p)"',
        'python3 -c "import shutil; p = \'/tmp\'; p += \'/../\'; shutil.rmtree(p)"',
        'python3 -c "import shutil; d = {\'p\': \'\'}; d[\'p\'] += \'/\'; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; a = [\'\']; a[0] += \'/\'; shutil.rmtree(a[0])"',
        'python3 -c "import os; c = \'rm \'; c += \'-rf /\'; os.system(c)"',
        (
            'python3 -c "import subprocess; c = [\'rm\', \'-rf\', \'\']; '
            'c[2] += \'/\'; subprocess.run(c)"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'\'])[0] += \'/\'; shutil.rmtree(d[\'a\'][0])"'
        ),
        # Reviewer r16 (5) + Challenger r16 (30) repros
        'env -S "rm -rf" /',
        'env -S"rm -rf" /',
        'env --split-string="rm -rf" /',
        'env --split-string "rm -rf" /',
        'echo / | env -S "xargs rm -rf"',
        'echo / | env -S"xargs rm -rf"',
        'echo / | xargs env -S "rm -rf"',
        'find / -maxdepth 0 -exec env -S "rm -rf" {} +',
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.setdefault(\'a\', \'/\'), d[\'a\']]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.setdefault(\'f\', shutil.rmtree), d[\'f\']]; b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'x, y = d.setdefault(\'a\', \'/\'), d[\'a\']; shutil.rmtree(y)"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'x, y = d.setdefault(\'f\', shutil.rmtree), d[\'f\']; y(\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'm = {\'x\': d.setdefault(\'a\', \'/\'), \'y\': d[\'a\']}; shutil.rmtree(m[\'y\'])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = dict(x=d.setdefault(\'a\', \'/\'), y=d[\'a\']); shutil.rmtree(b[\'y\'])"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'd[\'p\'], x = \'/\', 1; shutil.rmtree(d[\'p\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a[0], x = \'/\', 1; shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; d = {}; d[\'f\'], x = shutil.rmtree, 1; d[\'f\'](\'/\')"',
        'python3 -c "import shutil; a = [len]; a[0], x = shutil.rmtree, 1; a[0](\'/\')"',
        'python3 -c "import shutil; d = {}; (d[\'p\'], x) = [\'/\', 1]; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; d = {}; d[\'a\'], *x = \'/\', 1, 2; shutil.rmtree(d[\'a\'])"',
        (
            'python3 -c "import shutil; d = {}; '
            '(x, (d[\'p\'], y)) = (1, (\'/\', 2)); shutil.rmtree(d[\'p\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'b = [a.append(\'/\'), a[1]]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; a = [len]; '
            'b = [a.append(shutil.rmtree), a[1]]; b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.update(p=\'/\'), d[\'p\']]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.update(f=shutil.rmtree), d[\'f\']]; b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'b = [a.insert(0, \'/\'), a[0]]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'b = [a.extend([\'/\']), a[1]]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'b = [a.clear(), a.append(\'/\'), a[0]]; shutil.rmtree(b[2])"'
        ),
        'python3 -c "import shutil; a = [\'/\'] * 2; shutil.rmtree(a[0])"',
        'python3 -c "import shutil; a = 2 * [shutil.rmtree]; a[0](\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'd = dict(x=a[0], y=a.pop(0)); shutil.rmtree(d[\'x\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'd = dict(x=len(a.pop(0)), y=a[0]); shutil.rmtree(d[\'y\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'x\', shutil.rmtree]; '
            'd = dict(x=len(a.pop(0)), y=a[0]); d[\'y\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.setdefault(\'f\', shutil.rmtree), d[\'f\']]; b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.setdefault(\'p\', \'/\'), d[\'p\']]; shutil.rmtree(b[1])"'
        ),
        # Challenger r17 repros: shell group depth >= 3, shell pipeline prefixes, NamedExpr,
        # multi-arg Path, reverse/sort/popitem/fromkeys
        "((((echo / | xargs rm -rf); true); true); true); true",
        "(((((echo / | xargs rm -rf); true); true); true); true)",
        "((((echo / | xargs rm -rf) | cat) | cat) | cat) | cat",
        (
            "((((((((((echo / | xargs rm -rf); true); true); true); true); "
            "true); true); true); true); true); true"
        ),
        "! echo / | xargs rm -rf",
        "if ! echo / | xargs rm -rf; then :; fi",
        "if echo / | xargs rm -rf; then :; fi",
        "if false; then :; elif echo / | xargs rm -rf; then :; fi",
        "while echo / | xargs rm -rf; do break; done",
        "until echo / | xargs rm -rf; do break; done",
        "! (echo / | xargs rm -rf)",
        "! find / -maxdepth 0 -exec rm -rf {} +",
        "if (echo / | xargs rm -rf); then :; fi",
        "! { echo / | xargs rm -rf; }",
        (
            'python3 -c "import shutil; b = [len(p := \'/\'), p]; '
            'shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; x, y = len(p := \'/\'), p; '
            'shutil.rmtree(y)"'
        ),
        (
            'python3 -c "import shutil; d = dict(x=len(p := \'/\'), y=p); '
            'shutil.rmtree(d[\'y\'])"'
        ),
        (
            'python3 -c "import shutil; b = [f\'{(p := \\"/\\")}\', p]; '
            'shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; b = [str(f := shutil.rmtree), f]; '
            'b[1](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'x\': 1}; '
            'b = [d.setdefault(\'x\', (p := \'/\')), p]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; d = {\'x\': 1}; '
            'b = [d.get(\'x\', (p := \'/\')), p]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/tmp/work\', \'/\'))"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/tmp/work\', \'/etc\'))"'
        ),
        (
            'python3 -c "from pathlib import PurePosixPath; import shutil; '
            'shutil.rmtree(PurePosixPath(\'/tmp/work\', \'/etc\'))"'
        ),
        'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; a.reverse(); shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'a.sort(reverse=False); shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; d = {\'a\': \'/\'}; k, v = d.popitem(); shutil.rmtree(v)"',
        'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; k, f = d.popitem(); f(\'/\')"',
        'python3 -c "import shutil; d = dict.fromkeys([\'a\'], \'/\'); shutil.rmtree(d[\'a\'])"',
        'python3 -c "import shutil; d = dict.fromkeys([\'f\'], shutil.rmtree); d[\'f\'](\'/\')"',
        'python3 -c "import shutil; p = \'/\' + \'\'; shutil.rmtree(p)"',
        'python3 -c "import shutil; a = [\'/tmp/work\']; a += [\'/\']; shutil.rmtree(a[1])"',
        'python3 -c "import shutil; a = [\'/\'] + [\'/tmp/work\']; shutil.rmtree(a[0])"',
        # Challenger r18 repros + symmetric variants:
        # time/time -p before flow keywords & groups, case..esac, depth-9+ semi-pipe,
        # os.path.join, Path.joinpath, reversed(), sorted(), IfExp/Slice NamedExpr
        "time if echo / | xargs rm -rf; then :; fi",
        "time ! echo / | xargs rm -rf",
        "time (echo / | xargs rm -rf)",
        "time -p (echo / | xargs rm -rf)",
        "time { echo / | xargs rm -rf; }",
        "time -p { echo / | xargs rm -rf; }",
        'time -f "%e" rm -rf /',
        "case a in a) echo / | xargs rm -rf;; esac",
        "case a in a|b) echo / | xargs rm -rf;; esac",
        "case a in (a|b) echo / | xargs rm -rf;; esac",
        "case b in a) echo ok;; b|c) echo / | xargs rm -rf;; esac",
        "case a in a) echo ok;& b) echo / | xargs rm -rf;; esac",
        "case a in a) echo ok;;& a) echo / | xargs rm -rf;; esac",
        (
            "((((((((((echo /; echo /tmp) | xargs rm -rf); true); true); true); "
            "true); true); true); true); true); true"
        ),
        'python3 -c "import os, shutil; shutil.rmtree(os.path.join(\'/tmp/work\', \'/\'))"',
        (
            'python3 -c "import posixpath, shutil; '
            'shutil.rmtree(posixpath.join(\'/tmp/work\', \'/\'))"'
        ),
        (
            'python3 -c "from os.path import join; import shutil; '
            'shutil.rmtree(join(\'/tmp/work\', \'/\'))"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/tmp/work\').joinpath(\'/\'))"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'p = Path(\'/tmp/work\'); shutil.rmtree(p.joinpath(\'sub\').joinpath(\'/\'))"'
        ),
        (
            'python3 -c "from pathlib import PurePosixPath; import shutil; '
            'shutil.rmtree(PurePosixPath(\'/tmp/work\').joinpath(*[\'/\']))"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = list(reversed(a)); shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = tuple(reversed(a)); shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [*reversed(a)]; shutil.rmtree(b[0])"'
        ),
        'python3 -c "import shutil; a = [len, shutil.rmtree]; b = list(reversed(a)); b[0](\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = sorted(a); shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'b = sorted(a, key=None, reverse=False); shutil.rmtree(b[0])"'
        ),
        'python3 -c "import shutil; shutil.rmtree(p if (p := \'/\') else \'/tmp/work\')"',
        'python3 -c "import shutil; shutil.rmtree(\'/tmp/work\' if (p := \'\') else (q := \'/\'))"',
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp\']; '
            'b = [a[(i := 0):1], i]; shutil.rmtree(a[b[1]])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [a[0:(i := 1)], i]; shutil.rmtree(a[b[1]])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [a[unknown():(i := 1)], i]; shutil.rmtree(a[b[1]])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[(i := 0):1][i])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/tmp/work\']; '
            'a[(i := 0):1] = [\'/\']; shutil.rmtree(a[i])"'
        ),
        # Challenger r19 repros: ast.AugAssign int_vars updates
        (
            'python3 -c "import shutil; i = 0; i += 1; a = [\'/tmp/work\', \'/\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 1; i -= 1; a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 1; i *= 2; a = [\'/tmp/a\', \'/tmp/b\', \'/\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 5; i //= 2; a = [\'/tmp/a\', \'/tmp/b\', \'/\']; '
            'shutil.rmtree(a[i])"'
        ),
    ]
    for cmd in bypass_payloads:
        assert safety_floor("bash.exec", {"command": cmd}) is not None, f"Bypassed: {cmd!r}"
        assert safety_floor("turn.prompt", {"prompt": cmd}) is not None, f"Bypassed prompt: {cmd!r}"

    # Non-critical wrapper, find, xargs, subprocess, & shutil.rmtree paths remain allowed
    assert safety_floor("bash.exec", {"command": "sudo -u root ls -la /tmp"}) is None
    assert safety_floor("bash.exec", {"command": "sudo -Eu root ls -la /tmp"}) is None
    assert safety_floor("bash.exec", {"command": "env -u PATH ls -la /tmp"}) is None
    assert safety_floor("bash.exec", {"command": "sudo -i ls -la /tmp"}) is None
    assert safety_floor("bash.exec", {"command": "find /tmp -name '*.log'"}) is None
    assert safety_floor("bash.exec", {"command": "find / -name '*.log'"}) is None
    assert safety_floor("bash.exec", {"command": "find /tmp/work -delete"}) is None
    assert safety_floor("bash.exec", {"command": "find /tmp/work -exec rm -rf {} +"}) is None
    assert (
        safety_floor("bash.exec", {"command": r"find /tmp/work -exec sh -c 'rm -rf {}' \;"})
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'find /tmp/work -exec sh -c \'rm -rf "$1"\' _ {} +'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'find / -exec sh -c \'rm -rf "$1"\' _ /tmp/work {} +'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": r"find /tmp/work -exec bash -o errexit -c 'rm -rf {}' \;"},
        )
        is None
    )
    assert safety_floor("bash.exec", {"command": "find / -exec ls -la {} +"}) is None
    assert safety_floor("bash.exec", {"command": "echo /tmp/work | xargs rm -rf"}) is None
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'echo /tmp/work | xargs sh -c \'rm -rf "$1"\' _'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'echo /tmp/work | xargs sh -c \'rm -rf "$2"\' _ /tmp/safe'},
        )
        is None
    )
    assert safety_floor("bash.exec", {"command": "echo / | xargs -I% sh -c 'echo %'"}) is None
    assert (
        safety_floor("bash.exec", {"command": "echo /tmp/work | xargs -I% sh -c 'rm -rf %'"})
        is None
    )
    assert safety_floor("bash.exec", {"command": "echo / | xargs -I{} echo {}"}) is None
    assert safety_floor("bash.exec", {"command": "find /tmp -name '*.log' | xargs rm -f"}) is None
    assert safety_floor("bash.exec", {"command": "echo / | xargs ls -la"}) is None
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'python3 -c "import subprocess; subprocess.run([\'ls\', \'/tmp\'])"'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import subprocess; subprocess.run([\'ls\', \'-la\', \'/tmp\'])"'
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'python3 -c "import shutil; shutil.rmtree(\'/tmp/work\')"'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import shutil; a, b = \'/tmp/a\', \'/tmp/b\'; shutil.rmtree(a)"'
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import shutil; a, *b = \'/tmp/a\', \'/tmp/b\'; '
                    'shutil.rmtree(b[0])"'
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import shutil; d = {\'a\': {\'p\': \'/tmp/work\'}}; '
                    'shutil.rmtree(d[\'a\'][\'p\'])"'
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import shutil; d = {\'a\': [{\'p\': \'/tmp/work\'}]}; '
                    'shutil.rmtree(d[\'a\'][0].get(\'p\'))"'
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'python3 -c "import shutil; fns = [shutil.rmtree]; fns[0](\'/tmp/work\')"'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'python3 -c "import shutil; getattr(shutil, \'rmtree\')(\'/tmp/work\')"'},
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {"command": 'python3 -c "import shutil; x = \'work\'; shutil.rmtree(f\'/tmp/{x}\')"'},
        )
        is None
    )

    safe_r7_controls = [
        "echo /tmp/work | xargs --replace sh -c 'rm -rf {}'",
        "echo /tmp/work | xargs --replace rm -rf {}",
        "echo /tmp/work | xargs --eof sh -c 'rm -rf \"$1\"' _",
        "echo /tmp/work | xargs --eof rm -rf",
        "echo /tmp/work | xargs --max-lines sh -c 'rm -rf \"$1\"' _",
        "echo /tmp/work | xargs --max-lines rm -rf",
        "echo /tmp/work | xargs -e sh -c 'rm -rf \"$1\"' _",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$1\"' _ /tmp/safe",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$@\"' _ /tmp/safe",
        "echo /tmp/work | xargs sh -c 'rm -rf \"$0\"' /tmp/safe",
        "find /tmp/work -exec sh -c 'for p; do rm -rf \"$p\"; done' _ /tmp/safe {} +",
        "echo /tmp/work | xargs sh -c 'for p; do rm -rf \"$p\"; done' _ /tmp/safe",
        'python3 -c "import shutil; d = {}; p = d.get(\'p\', \'/tmp/work\'); shutil.rmtree(p)"',
        (
            'python3 -c "import shutil; d = {\'x\': 1}; '
            'p = d.get(\'p\', \'/tmp/work\'); shutil.rmtree(p)"'
        ),
        'python3 -c "import shutil; a = [\'/tmp/work\']; shutil.rmtree(*a)"',
        'python3 -c "import shutil; kw = {\'path\': \'/tmp/work\'}; shutil.rmtree(**kw)"',
        'python3 -c "import shutil; d = {}; d[\'p\'] = \'/tmp/work\'; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; d = {}; d |= {\'p\': \'/tmp/work\'}; shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; a = []; a.append(\'/tmp/work\'); shutil.rmtree(a[0])"',
        'python3 -c "import shutil, builtins; builtins.getattr(shutil, \'rmtree\')(\'/tmp/work\')"',
    ]
    for safe_cmd in safe_r7_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r8_controls = [
        'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; d2 = d; shutil.rmtree(d2[\'p\'])"',
        (
            'python3 -c "import shutil; fns = {\'r\': shutil.rmtree}; '
            'f2 = fns; f2[\'r\'](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; a = [{\'p\': \'/tmp/work\'}]; '
            'b = a; shutil.rmtree(b[0][\'p\'])"'
        ),
        'python3 -c "import shutil; a = [shutil.rmtree]; b = a; b[0](\'/tmp/work\')"',
        'python3 -c "import shutil; d = dict(p=\'/tmp/work\'); shutil.rmtree(d[\'p\'])"',
        'python3 -c "import shutil; kw = dict(path=\'/tmp/work\'); shutil.rmtree(**kw)"',
        (
            'python3 -c "import subprocess; kw = dict(args=[\'ls\', \'-la\', \'/tmp/work\']); '
            'subprocess.run(**kw)"'
        ),
        'python3 -c "import shutil; d = {}; d.update(p=\'/tmp/work\'); shutil.rmtree(d[\'p\'])"',
        (
            'python3 -c "import shutil; f = {}; '
            'f.update(r=shutil.rmtree); f[\'r\'](\'/tmp/work\')"'
        ),
        'python3 -c "import shutil; a = list((\'/tmp/work\',)); shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; d = {}; '
            'd = d | {\'p\': \'/tmp/work\'}; shutil.rmtree(d[\'p\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\'] + [\'/tmp/safe\']; '
            'shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': []}; '
            'd[\'a\'].append(\'/tmp/work\'); shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'p = d.setdefault(\'p\', \'/tmp/work\'); shutil.rmtree(p)"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'p = d.setdefault(\'p\', \'/\'); shutil.rmtree(p)"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a.insert(0, \'/tmp/safe\'); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/\'}; '
            'd.clear(); shutil.rmtree(d.get(\'p\', \'/tmp/work\'))"'
        ),
        "(rm -rf /tmp/work)",
        "{ rm -rf /tmp/work; }",
        "find /tmp/work -exec sh -c '(rm -rf \"$1\")' _ {} +",
        "echo /tmp/work | xargs sh -c '(rm -rf \"$1\")' _",
        "find /tmp/work -exec sh -c '{ rm -rf \"$1\"; }' _ {} +",
        "echo /tmp/work | xargs sh -c '{ rm -rf \"$1\"; }' _",
        "Can you check Pump 34 (in area 1)?",
    ]
    for safe_cmd in safe_r8_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r9_controls = [
        (
            'python3 -c "import shutil; pairs = [(\'r\', shutil.rmtree)]; '
            'f = dict(pairs); f[\'r\'](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; pairs = [(\'r\', shutil.rmtree)]; '
            'f = {}; f.update(pairs); f[\'r\'](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'd2 = d.copy(); shutil.rmtree(d2[\'p\'])"'
        ),
        (
            'python3 -c "import shutil; f = {\'r\': shutil.rmtree}; '
            'f2 = f.copy(); f2[\'r\'](\'/tmp/work\')"'
        ),
        'python3 -c "import shutil; a = [\'/tmp/work\']; b = a.copy(); shutil.rmtree(b[0])"',
        'python3 -c "import shutil; a = [shutil.rmtree]; b = a.copy(); b[0](\'/tmp/work\')"',
        'python3 -c "import shutil; d = {\'/tmp/work\': 1}; a = list(d); shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0].append(shutil.rmtree); a[0][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0].insert(0, shutil.rmtree); a[0][0](\'/tmp/work\')"'
        ),
        "{ echo /tmp/work; } | xargs rm -rf",
        "{ echo /tmp/work ; } | xargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) | xargs rm -rf",
        "find /tmp/work -exec sh -c 'echo ok & rm -rf \"$1\"' _ {} +",
        "echo /tmp/work | xargs sh -c 'echo ok & rm -rf \"$1\"' _",
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = fns + [\'/tmp/work\']; shutil.rmtree(a[1])"'
        ),
        "echo ok >/dev/null 2>&1",
        "echo ok &>/dev/null",
        "echo ok |& cat",
    ]
    for safe_cmd in safe_r9_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r10_controls = [
        (
            'python3 -c "import shutil; a = [[\'/tmp/work\']]; '
            'a[0] += [shutil.rmtree]; a[0][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/work\']}; '
            'd[\'a\'] += [shutil.rmtree]; d[\'a\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; a = [[shutil.rmtree]]; '
            'a[0] += [\'/tmp/work\']; a[0][0](a[0][1])"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [shutil.rmtree]}; '
            'd[\'a\'] += [\'/tmp/work\']; d[\'a\'][0](d[\'a\'][1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = fns.copy() + [\'/tmp/work\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = list(fns) + [\'/tmp/work\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = [*fns] + [\'/tmp/work\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = [*fns, \'/tmp/work\']; shutil.rmtree(a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\']; '
            'a = paths.copy() + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\']; '
            'a = list(paths) + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\']; '
            'a = [*paths] + [shutil.rmtree]; a[1](a[0])"'
        ),
        'python3 -c "import shutil; d = {\'/tmp/work\': 1}; a = [*d]; shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; d = {\'/tmp/work\': 1}; '
            'a = list(d.keys()); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'/tmp/work\': 1}; '
            'a = [*d.keys()]; shutil.rmtree(a[0])"'
        ),
        "(echo /tmp/work; echo /tmp/safe) 2>/dev/null | xargs rm -rf",
        "{ echo /tmp/work; echo /tmp/safe; } 2>/dev/null | xargs rm -rf",
        "{ echo /tmp/work; } 2>&1 | xargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) >/dev/null 2>&1 | xargs rm -rf",
        "{ echo /tmp/work; }>/dev/null | xargs rm -rf",
    ]
    for safe_cmd in safe_r10_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r11_controls = [
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).append(shutil.rmtree); '
            'd[\'a\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [shutil.rmtree]).append(\'/tmp/work\'); '
            'd[\'a\'][0](d[\'a\'][1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).extend([shutil.rmtree]); '
            'd[\'a\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\']).insert(0, shutil.rmtree); '
            'd[\'a\'][0](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {}).setdefault(\'b\', [\'/tmp/work\']).append(shutil.rmtree); '
            'd[\'a\'][\'b\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import os, shutil; d = os.environ.copy(); '
            'd[\'a\'] = [\'/tmp/work\']; d[\'a\'][0] = shutil.rmtree; '
            'd[\'a\'][0](\'/tmp/work\')"'
        ),
        'python3 -c "import shutil; a = [0]; a += [shutil.rmtree, \'/tmp/work\']; a[1](a[2])"',
        (
            'python3 -c "import shutil; d = {\'a\': [0]}; '
            'd[\'a\'] += [shutil.rmtree, \'/tmp/work\']; d[\'a\'][1](d[\'a\'][2])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = fns[:] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\']; '
            'a = paths[:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'/tmp/work\': shutil.rmtree}; '
            'a = [*d]; b = list(d.values()); b[0](a[0])"'
        ),
        "(echo /tmp/work; echo /tmp/safe) 2>| /dev/null | xargs rm -rf",
        "{ echo /tmp/work; echo /tmp/safe; } 2>| /dev/null | xargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) 2>/dev/null \\\n| xargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) {fd}>/dev/null | xargs rm -rf",
        "echo /tmp/work | 2>/dev/null xargs rm -rf",
        "2>/dev/null echo /tmp/work | xargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) 2>/dev/null</dev/null | xargs rm -rf",
        'python3 -c "import shutil; a = [0]; shutil.rmtree(a[0])"',
    ]
    for safe_cmd in safe_r11_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r12_controls = [
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'f\'] = shutil.rmtree; d[\'a\'][\'f\'](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'p\'] = \'/tmp/work\'; shutil.rmtree(d[\'a\'][\'p\'])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [None])[0] = shutil.rmtree; d[\'a\'][0](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [\'/tmp/work\'])[0] = \'/tmp/safe\'; shutil.rmtree(d[\'a\'][0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {\'b\': [\'/tmp/work\']})[\'b\'].append(shutil.rmtree); '
            'd[\'a\'][\'b\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {}).setdefault(\'b\', {})[\'f\'] = shutil.rmtree; '
            'd[\'a\'][\'b\'][\'f\'](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', {})[\'b\'] = [\'/tmp/work\']; '
            'd[\'a\'][\'b\'].append(shutil.rmtree); d[\'a\'][\'b\'][1](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/tmp/work\']}; '
            'd.setdefault(\'a\', [])[0] = shutil.rmtree; d[\'a\'][0](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree]; '
            'a = fns[0:] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[0:1] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/safe\', \'/tmp/work\']; '
            'a = paths[1:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/safe\', \'/tmp/work\']; '
            'a = paths[-1:] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/work\', \'/tmp/safe\']; '
            'a = paths[::-1] + [shutil.rmtree]; a[2](a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[::2] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        'python3 -c "import shutil; fns = [shutil.rmtree]; a = fns[::0]"',
        "echo /tmp/work | env 2>/dev/null xargs rm -rf",
        "find /tmp/work -maxdepth 0 -exec env 2>/dev/null rm -rf {} +",
        "(echo /tmp/work; echo /tmp/safe) 2>/dev/null |\nxargs rm -rf",
        "echo /tmp/work |\nxargs rm -rf",
        "(echo /tmp/work; echo /tmp/safe) 2>/dev/null |&\nxargs rm -rf",
    ]
    for safe_cmd in safe_r12_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r13_controls = [
        "echo /tmp/work |\\\nxargs rm -rf",
        "echo /tmp/work | \\\nxargs rm -rf",
        "echo /tmp/work |\t\\\n\txargs rm -rf",
        "echo /tmp/work | env \\\n xargs rm -rf",
        "find /tmp/work -maxdepth 0 -exec \\\nrm -rf {} +",
        "echo /tmp/work | # comment\nxargs rm -rf",
        "echo /tmp/work |&\n# comment\nxargs rm -rf",
        "echo /tmp/work |\n# c\nxargs rm -rf",
        "bash -c $'echo /tmp/work |\\nxargs rm -rf'",
        "echo /tmp/work | xargs 2>/dev/null -I {} rm -rf {}",
        "echo /tmp/work | xargs 2>/dev/null -n 1 sh -c 'rm -rf \"$1\"' _",
        "echo /tmp/work | env 2>/dev/null xargs 2>/dev/null -n 1 rm -rf",
        "find 2>/dev/null -L /tmp/work -maxdepth 0 -delete",
        "find 2>/dev/null -H /tmp/work -maxdepth 0 -exec rm -rf {} +",
        "echo /tmp/work | env>/dev/null xargs rm -rf",
        "echo /tmp/work | xargs>/dev/null rm -rf",
        "find /tmp/work -maxdepth 0 -exec env>/dev/null rm -rf {} +",
        "rm>/dev/null -rf /tmp/work",
        "find>/dev/null /tmp/work -maxdepth 0 -exec rm -rf {} +",
        "env>/dev/null rm -v -r -f /tmp/work",
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[0:1:None] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; fns = [shutil.rmtree, len]; '
            'a = fns[None:1] + [\'/tmp/work\']; a[0](a[1])"'
        ),
        (
            'python3 -c "import shutil; paths = [\'/tmp/safe\', \'/tmp/work\']; '
            'a = paths[1:None] + [shutil.rmtree]; a[1](a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [len])[0:1] = [shutil.rmtree]; d[\'a\'][0](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; a = [len]; '
            'a[0:1] = [shutil.rmtree]; a[0](\'/tmp/work\')"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'd.setdefault(\'a\', [shutil.rmtree])[0:1] = [len]; d[\'a\'][0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [shutil.rmtree]; '
            'a[0:1] = [len]; a[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [shutil.rmtree]; '
            'a[0:1] = []; a[0](\'/\')"'
        ),
        'python3 -c "import shutil; fns = [shutil.rmtree]; a = fns[0:1:0]"',
        'python3 -c "import shutil; a = [len]; a[0:2:2] = [shutil.rmtree, len]"',
        "echo 'hello\\\nworld' 'a>b' \"c>d\"",
    ]
    for safe_cmd in safe_r13_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    for safe_prompt in (
        "What's 2>1? Don't check $'USD' or foo#bar.",
        "I'm checking 'a\\\nb' and a>b",
        "Explain why \\$'xargs' and $\\n'USD' stay literal in prose.",
    ):
        assert safety_floor("turn.prompt", {"prompt": safe_prompt}) is None, safe_prompt

    safe_r14_controls = [
        # M14 & M16 negative controls
        (
            'python3 -c "import shutil; d = {\'a\': \'/\'}; '
            'del d[\'a\']; shutil.rmtree(d.get(\'a\', \'/tmp/work\'))"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'a.pop(0); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; d = {}; '
            'p = d.pop(\'missing\', a[0]); shutil.rmtree(p)"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'p = d.pop(\'p\', \'/\'); shutil.rmtree(p)"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'del d[\'f\']; d.get(\'f\', len)(\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'd.pop(\'f\'); d.get(\'f\', len)(\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'a.pop(99); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\']; '
            'i = 0; a.pop(i); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [a[0], a.pop(0)]; shutil.rmtree(b[0])"'
        ),
        'python3 -c "import shutil; a = [shutil.rmtree]; a[0:1] = \'/\'; a[0](\'/\')"',
        'python3 -c "import shutil; a = [len]; a[0:1:2] += [shutil.rmtree]; a[0](\'/\')"',
        'python3 -c "import shutil; a = [\'/\']; a[0:1] = \'w\'; shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [\'/\']; '
            'a[0:1] = {\'/tmp/work\': 1}; shutil.rmtree(a[0])"'
        ),
        'bash -c "echo / | \\\\$\'xargs\' rm -rf"',
        r'bash -c "echo / | \\nxargs rm -rf"',
        'bash -c "echo /tmp/work | \\$\'xargs\' rm -rf"',
        "echo /tmp/work | $\\\n'xargs' rm -rf",
        "rm -rf $\\\n'/tmp/work'",
        "echo 'a\\\nb' $'hello\\\nworld'",
    ]
    for safe_cmd in safe_r14_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    # Verify single-quoted & escaped-backslash line continuations remain literal
    from src.engine.policy_gateway import _strip_shell_line_continuations

    assert _strip_shell_line_continuations("'a\\\nb'") == "'a\\\nb'"
    assert _strip_shell_line_continuations("a\\\\\nb") == "a\\\\\nb"
    assert _strip_shell_line_continuations("a\\\\\\\nb") == "a\\\\b"
    assert _strip_shell_line_continuations("$'a\\\nb'") == "$'a\\\nb'"
    assert _strip_shell_line_continuations("$\\\n'xargs'") == "$'xargs'"

    safe_r15_controls = [
        '$"echo" /tmp/work',
        'rm -rf $"/tmp/work"',
        'echo /tmp/work | $"xargs" -I {} rm -rf {}',
        'bash -c "echo / | \\\\$"xargs" -I {} rm -rf {}"',
        'bash -c "echo / | \\\\$\\"xargs\\" -I {} rm -rf {}"',
        '$"r\\"m" -rf /',
        'python3 -c "import shutil; p = \'/tmp/work\'; p += \'/sub\'; shutil.rmtree(p)"',
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'd[\'p\'] += \'/sub\'; shutil.rmtree(d[\'p\'])"'
        ),
        'python3 -c "import shutil; a = [\'/tmp/work\']; a[0] += \'/sub\'; shutil.rmtree(a[0])"',
        'python3 -c "import os; c = \'ls \'; c += \'-la /tmp/work\'; os.system(c)"',
        (
            'python3 -c "import subprocess; c = [\'ls\', \'-la\', \'/tmp\']; '
            'c[2] += \'/work\'; subprocess.run(c)"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [a[0], len(a.pop(0))]; shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; idx = [0]; a = [\'/\', \'/tmp/work\']; '
            'del a[idx.pop()]; shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; k = [\'f\']; d = {\'f\': len}; d[k.pop(0)](\'/\')"',
    ]
    for safe_cmd in safe_r15_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    for safe_prompt in (
        'How does $"USD" and $\'USD\' work in bash?',
        'Explain why $"100" and $"" stay literal in prose.',
        "In Python, p = ''; p += '/'; d[k.pop(0)] = '/' mutates containers.",
    ):
        assert safety_floor("turn.prompt", {"prompt": safe_prompt}) is None, safe_prompt

    safe_r16_controls = [
        'env -S "rm -rf" /tmp/work',
        'echo /tmp/work | env -S "xargs rm -rf"',
        (
            'python3 -c "import shutil; d = {\'p\': \'/\'}; '
            'd[\'p\'], x = \'/tmp/work\', 1; shutil.rmtree(d[\'p\'])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\']; '
            'a[0], x = \'/tmp/work\', 1; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/\'}; '
            'b = [d.update(p=\'/tmp/work\'), d[\'p\']]; shutil.rmtree(b[1])"'
        ),
        (
            'python3 -c "import shutil; d = {}; '
            'b = [d.get(\'x\'), d.setdefault(\'x\', \'/\')]; shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'd = dict(x=a[0], y=len(a.pop(0))); shutil.rmtree(d[\'x\'])"'
        ),
        (
            'python3 -c "import shutil; d = {\'p\': \'/tmp/work\'}; '
            'd[\'p\'], x = \'/\', d[\'p\']; shutil.rmtree(x)"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'a[0], a[1] = a[1], a[0]; shutil.rmtree(a[0])"'
        ),
        'python3 -c "import shutil; a = [\'/tmp/work\'] * 2; shutil.rmtree(a[0])"',
        'python3 -c "import shutil; a = 2 * [shutil.rmtree]; a[0](\'/tmp/work\')"',
        'python3 -c "import shutil; a = [\'/tmp/work\'] * 64; b = a * 64; shutil.rmtree(b[0])"',
    ]
    for safe_cmd in safe_r16_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r17_controls = [
        "(((((echo /tmp/work | xargs rm -rf); true); true); true); true)",
        (
            "((((((((((echo /tmp/work | xargs rm -rf); true); true); true); true); "
            "true); true); true); true); true); true"
        ),
        "! echo /tmp/work | xargs rm -rf",
        "if echo /tmp/work | xargs rm -rf; then :; fi",
        "if false; then :; elif echo /tmp/work | xargs rm -rf; then :; fi",
        "while echo /tmp/work | xargs rm -rf; do break; done",
        "until echo /tmp/work | xargs rm -rf; do break; done",
        "! (echo /tmp/work | xargs rm -rf)",
        "! find /tmp/work -maxdepth 0 -exec rm -rf {} +",
        'python3 -c "import shutil; b = [len(p := \'/tmp/work\'), p]; shutil.rmtree(b[1])"',
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/\', \'tmp/work\'))"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            's = unknown(); shutil.rmtree(Path(\'/\', s))"'
        ),
        'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; a.reverse(); shutil.rmtree(a[0])"',
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'a.sort(reverse=True); shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree, \'x\': 1}; '
            'k, f = d.popitem(); f(\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'd.update({\'f\': len}); d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'd.update(**{\'f\': len}); d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'd |= {\'f\': len}; d[\'f\'](\'/\')"'
        ),
        (
            'python3 -c "import shutil; d = {\'f\': shutil.rmtree}; '
            'd = d | {\'f\': len}; d[\'f\'](\'/\')"'
        ),
        'python3 -c "import shutil; d = {\'f\': shutil.rmtree, \'f\': len}; d[\'f\'](\'/\')"',
        'python3 -c "import shutil; f = shutil.rmtree; f = len; f(\'/\')"',
        (
            'python3 -c "import shutil; a = [\'/\'] * 1024; '
            'a[0:0] = [\'/tmp/work\']; shutil.rmtree(a[0])"'
        ),
        (
            'python3 -c "import shutil; d = {\'a\': [\'/\'] * 1024}; '
            'd[\'a\'][0:0] = [\'/tmp/work\']; shutil.rmtree(d[\'a\'][0])"'
        ),
    ]
    for safe_cmd in safe_r17_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    safe_r18_controls = [
        "time if echo /tmp/work | xargs rm -rf; then :; fi",
        "time ! echo /tmp/work | xargs rm -rf",
        "time (echo /tmp/work | xargs rm -rf)",
        "time -p (echo /tmp/work | xargs rm -rf)",
        "time { echo /tmp/work | xargs rm -rf; }",
        'time -f "%e" rm -rf /tmp/work',
        "case a in a) echo /tmp/work | xargs rm -rf;; esac",
        "case a in a|b) echo /tmp/work | xargs rm -rf;; esac",
        "case a in (a|b) echo /tmp/work | xargs rm -rf;; esac",
        "case a in a) echo ok;; b|c) echo /tmp/work | xargs rm -rf;; esac",
        (
            "((((((((((echo /tmp/work; echo /tmp) | xargs rm -rf); true); true); true); "
            "true); true); true); true); true); true"
        ),
        'python3 -c "import os, shutil; shutil.rmtree(os.path.join(\'/\', \'tmp/work\'))"',
        'python3 -c "import os, shutil; shutil.rmtree(os.path.join(\'/\', unknown()))"',
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/\').joinpath(\'tmp/work\'))"'
        ),
        (
            'python3 -c "from pathlib import Path; import shutil; '
            'shutil.rmtree(Path(\'/\').joinpath(unknown()))"'
        ),
        'python3 -c "import shutil; shutil.rmtree(\'/\'.join([\'\', \'tmp/work\']))"',
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'b = list(reversed(a)); shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [shutil.rmtree, len]; '
            'b = list(reversed(a)); b[0](\'/\')"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'b = sorted(a, reverse=True); shutil.rmtree(b[0])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'b = sorted(a, key=len); shutil.rmtree(b[0])"'
        ),
        'python3 -c "import shutil; shutil.rmtree(p if (p := \'/tmp/work\') else \'/tmp/safe\')"',
        'python3 -c "import shutil; shutil.rmtree(p if (p := \'/tmp/work\') else \'/\')"',
        'python3 -c "import shutil; shutil.rmtree(\'/\' if (p := \'\') else \'/tmp/work\')"',
        (
            'python3 -c "import shutil; a = [\'/tmp/work\', \'/\']; '
            'b = [a[(i := 0):1], i]; shutil.rmtree(a[b[1]])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'b = [a[0:(i := 1)], i]; shutil.rmtree(a[b[1]])"'
        ),
        (
            'python3 -c "import shutil; a = [\'/\', \'/tmp/work\']; '
            'a[(i := 0):1] = [\'/tmp/work\']; shutil.rmtree(a[i])"'
        ),
        # Challenger r19 safe controls: ast.AugAssign int_vars updates & invalidation
        (
            'python3 -c "import shutil; i = 0; i += 1; a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 1; i -= 1; a = [\'/tmp/work\', \'/\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 0; i += unknown(); a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 0; i /= 2; a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[i])"'
        ),
        (
            'python3 -c "import shutil; i = 0; i = unknown(); a = [\'/\', \'/tmp/work\']; '
            'shutil.rmtree(a[i])"'
        ),
    ]
    for safe_cmd in safe_r18_controls:
        assert safety_floor("bash.exec", {"command": safe_cmd}) is None, safe_cmd
        assert safety_floor("turn.prompt", {"prompt": safe_cmd}) is None, safe_cmd

    prose_r18_controls = [
        (
            "In the shell script we run 'time if' and 'case a in a) echo /tmp/work; esac' "
            "to inspect timing logs cleanly."
        ),
        (
            "Please explain how os.path.join('/tmp/work', 'sub'), Path('/tmp/work').joinpath('a'), "
            "list(reversed(['a', 'b'])), and sorted(['b', 'a']) behave in Python."
        ),
    ]
    for prose_prompt in prose_r18_controls:
        assert safety_floor("turn.prompt", {"prompt": prose_prompt}) is None, prose_prompt

    # 2s SIGALRM linear-time stress checks for deeply nested shell groups (n=4000)
    # interleaved pipe groups (n=1500/4000, bash -c n=700), and exponential O(2^N) DoS payloads
    def _on_alarm(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SIGALRM 2s timeout")

    prev_handler = signal.signal(signal.SIGALRM, _on_alarm)
    try:
        for label, group_cmd, expect_block in (
            ("echo_4000_parens", "echo " + ("(" * 4000) + "ok" + (")" * 4000), False),
            ("pure_4000_parens", ("(" * 4000) + "echo ok" + (")" * 4000), False),
            ("crit_4000_parens", ("(" * 4000) + "rm -rf /" + (")" * 4000), True),
            ("pure_4000_braces", ("{ " * 4000) + "echo ok;" + (" }" * 4000), False),
            ("crit_4000_braces", ("{ " * 4000) + "rm -rf /;" + (" }" * 4000), True),
            ("pipe_grp_1500_safe", ("(" * 1500) + "echo ok | cat" + (") | cat" * 1500), False),
            (
                "pipe_grp_1500_crit",
                ("(" * 1500) + "echo / | xargs rm -rf" + (") | cat" * 1500),
                True,
            ),
            ("pipe_grp_4000_safe", ("(" * 4000) + "echo ok | cat" + (") | cat" * 4000), False),
            (
                "pipe_grp_4000_crit",
                ("(" * 4000) + "echo / | xargs rm -rf" + (") | cat" * 4000),
                True,
            ),
            (
                "bash_c_pipe_700_safe",
                'bash -c "' + ("(" * 700) + "echo ok | cat" + (") | cat" * 700) + '"',
                False,
            ),
            (
                "bash_c_pipe_700_crit",
                'bash -c "' + ("(" * 700) + "echo / | xargs rm -rf" + (") | cat" * 700) + '"',
                True,
            ),
            ("xargs_pipe_1500_safe", ("(" * 1500) + "echo ok" + (") | xargs rm -rf" * 1500), False),
            ("xargs_pipe_1500_crit", ("(" * 1500) + "echo /" + (") | xargs rm -rf" * 1500), True),
        ):
            signal.alarm(2)
            t0 = time.monotonic()
            try:
                res_b = safety_floor("bash.exec", {"command": group_cmd})
                res_p = safety_floor("turn.prompt", {"prompt": group_cmd})
            finally:
                signal.alarm(0)
            assert time.monotonic() - t0 < 0.8, f"Slow nested group stress: {label}"
            if expect_block:
                assert res_b is not None and res_p is not None, label
            else:
                assert res_b is None and res_p is None, label

        dos_doubling_cases = (
            (
                "DOS_LIST_DOUBLING_ADD_25",
                'python3 -c "import shutil; a = [\'/tmp/work\']; '
                + "a = a + a; " * 25
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_LIST_DOUBLING_AUGADD_25",
                'python3 -c "import shutil; a = [\'/tmp/work\']; '
                + "a += a; " * 25
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_LIST_EXTEND_SELF_25",
                'python3 -c "import shutil; a = [\'/tmp/work\']; '
                + "a.extend(a); " * 25
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_LIST_SLICE_DOUBLING_25",
                'python3 -c "import shutil; a = [\'/tmp/work\']; '
                + "a[0:0] = a; " * 25
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_STR_DOUBLING_ADD_27",
                'python3 -c "import shutil; p = \'a\'; '
                + "p = p + p; " * 27
                + 'shutil.rmtree(p)"',
            ),
            (
                "DOS_STR_DOUBLING_AUGADD_28",
                'python3 -c "import shutil; p = \'a\'; '
                + "p += p; " * 28
                + 'shutil.rmtree(p)"',
            ),
            (
                "DOS_LIST_MULT_THEN_ADD_18",
                'python3 -c "import shutil; a = [\'/tmp/work\'] * 64; '
                + "a = a + a; " * 18
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_STARRED_DOUBLING_25",
                'python3 -c "import shutil; a = [\'/tmp/work\']; '
                + "a = [*a, *a]; " * 25
                + 'shutil.rmtree(a[0])"',
            ),
            (
                "DOS_FSTRING_DOUBLING_27",
                'python3 -c "import shutil; p = \'a\'; '
                + "p = f'{p}{p}'; " * 27
                + 'shutil.rmtree(p)"',
            ),
            (
                "DOS_NESTED_SLICE_DOUBLING_25",
                'python3 -c "import shutil; d = {\'a\': [\'/tmp/work\']}; '
                + "d['a'][0:0] = d['a']; " * 25
                + 'shutil.rmtree(d[\'a\'][0])"',
            ),
        )
        for dos_label, dos_cmd in dos_doubling_cases:
            signal.alarm(2)
            t0 = time.monotonic()
            try:
                res_b = safety_floor("bash.exec", {"command": dos_cmd})
                res_p = safety_floor("turn.prompt", {"prompt": dos_cmd})
            finally:
                signal.alarm(0)
            assert time.monotonic() - t0 < 0.2, f"Slow O(2^N) DoS case: {dos_label}"
            assert res_b is None and res_p is None, dos_label
    finally:
        signal.signal(signal.SIGALRM, prev_handler)

    # Stress check for 300-statement del / pop / slice-augassign / str-augassign chains
    for stmt in ("del a[0]", "a.pop(0)", "a[0:1] += ['/tmp/work']", "p += '/sub'"):
        chain_cmd = (
            'python3 -c "import shutil; p = \'/tmp/work\'; a = list([\'/tmp/work\'] * 305); '
            + "; ".join([stmt] * 300)
            + '; shutil.rmtree(a[0]); shutil.rmtree(p)"'
        )
        t0 = time.monotonic()
        assert safety_floor("bash.exec", {"command": chain_cmd}) is None
        assert time.monotonic() - t0 < 1.0, f"Slow 300-statement chain: {stmt}"

    # Deep & self-referential AST stress checks must never raise RecursionError or hang O(2^N)
    deep_calls = "f(" * 300 + "'/'" + ")" * 300
    assert (
        safety_floor("bash.exec", {"command": f'python3 -c "import shutil; {deep_calls}"'})
        is None
    )
    deep_add = " + ".join(["['/tmp/work']"] * 350)
    assert (
        safety_floor(
            "bash.exec",
            {"command": f'python3 -c "import shutil; a = {deep_add}; shutil.rmtree(a[0])"'},
        )
        is None
    )
    deep_bitor = " | ".join(["{'p': '/tmp/work'}"] * 350)
    assert (
        safety_floor(
            "bash.exec",
            {"command": f'python3 -c "import shutil; d = {deep_bitor}; shutil.rmtree(d[\'p\'])"'},
        )
        is None
    )
    for op_expr in (
        "fns.copy()",
        "list(fns)",
        "[*fns]",
        "fns[:]",
        "fns[0:]",
        "fns[::-1]",
        "fns[::2]",
    ):
        deep_fn_pad = " + ".join([op_expr] * 350)
        safe_pad_cmd = (
            f'python3 -c "import shutil; fns = [shutil.rmtree]; '
            f'a = {deep_fn_pad} + [\'/tmp/work\']; shutil.rmtree(a[-1])"'
        )
        crit_pad_cmd = (
            f'python3 -c "import shutil; fns = [shutil.rmtree]; '
            f'a = {deep_fn_pad} + [\'/\']; shutil.rmtree(a[-1])"'
        )
        t0 = time.monotonic()
        assert safety_floor("bash.exec", {"command": safe_pad_cmd}) is None
        assert safety_floor("bash.exec", {"command": crit_pad_cmd}) is not None
        assert time.monotonic() - t0 < 1.0, f"Slow 350-deep padding chain: {op_expr}"
    for dict_init in ("{}", "{'a': '/tmp/work'}", "{'a': {}}"):
        for method_call in (
            ".get('a')" * 350,
            ".setdefault('a')" * 350,
            ".setdefault('a', {})" * 350,
        ):
            cmd = f'python3 -c "import shutil; d = {dict_init}; shutil.rmtree(d{method_call})"'
            t0 = time.monotonic()
            assert safety_floor("bash.exec", {"command": cmd}) is None
            assert safety_floor("turn.prompt", {"prompt": cmd}) is None
            assert time.monotonic() - t0 < 1.0, f"Slow chain: {dict_init} {method_call[:16]}"
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    'python3 -c "import shutil; d = {}; d[\'self\'] = d; d2 = d; '
                    'd2.update(k=d2); shutil.rmtree(d2.get(\'p\', \'/tmp/work\'))"'
                )
            },
        )
        is None
    )

    # Structural complexity budgets fail closed under 2s SIGALRM
    prev_budget_handler = signal.signal(signal.SIGALRM, _on_alarm)
    try:
        shell_budget_cmd = "a;" * 66_000
        signal.alarm(2)
        t_shell_budget = time.monotonic()
        try:
            shell_budget_res = safety_floor("bash.exec", {"command": shell_budget_cmd})
        finally:
            signal.alarm(0)
        assert shell_budget_res == "safety_floor:shell_complexity_budget_exceeded"
        assert time.monotonic() - t_shell_budget < 1.5

        ast_budget_cmd = (
            'python3 -c "import shutil; x=0;' + ("x+=0;" * 15_000) + 'shutil.rmtree(\'/tmp/work\')"'
        )
        signal.alarm(2)
        t_ast_budget = time.monotonic()
        try:
            ast_budget_res = safety_floor("bash.exec", {"command": ast_budget_cmd})
        finally:
            signal.alarm(0)
        assert ast_budget_res == "safety_floor:python_ast_complexity_budget_exceeded"
        assert time.monotonic() - t_ast_budget < 1.5

        # Challenger r19: pipe_stages budget fail-closed + O(N) xargs + AST RecursionError
        pipe_66k_cmd = ("a|" * 66_000) + "b"
        signal.alarm(2)
        t_pipe_66k = time.monotonic()
        try:
            pipe_66k_res = safety_floor("bash.exec", {"command": pipe_66k_cmd})
            pipe_66k_prompt = safety_floor("turn.prompt", {"prompt": pipe_66k_cmd})
        finally:
            signal.alarm(0)
        assert pipe_66k_res == "safety_floor:shell_complexity_budget_exceeded"
        assert pipe_66k_prompt == "safety_floor:shell_complexity_budget_exceeded"
        assert time.monotonic() - t_pipe_66k < 1.5

        for xargs_label, xargs_cmd, expect_xargs_block in (
            ("PIPE_XARGS_ON2_500", ("echo ok | " * 500) + ("xargs rm -rf | " * 500) + "cat", False),
            (
                "PIPE_XARGS_ON2_1000",
                ("echo ok | " * 1000) + ("xargs rm -rf | " * 1000) + "cat",
                False,
            ),
            (
                "PIPE_XARGS_ON2_CRIT",
                ("echo ok | " * 500) + "echo / | " + ("xargs rm -rf | " * 500) + "cat",
                True,
            ),
        ):
            signal.alarm(2)
            t_xargs = time.monotonic()
            try:
                res_xb = safety_floor("bash.exec", {"command": xargs_cmd})
                res_xp = safety_floor("turn.prompt", {"prompt": xargs_cmd})
            finally:
                signal.alarm(0)
            assert time.monotonic() - t_xargs < 0.8, f"Slow xargs pipeline: {xargs_label}"
            if expect_xargs_block:
                assert res_xb is not None and res_xp is not None, xargs_label
            else:
                assert res_xb is None and res_xp is None, xargs_label

        pipe_unique_30k = " | ".join(f"echo {i}" for i in range(30_000))
        signal.alarm(2)
        t_unique = time.monotonic()
        try:
            assert safety_floor("bash.exec", {"command": pipe_unique_30k}) is None
        finally:
            signal.alarm(0)
        assert time.monotonic() - t_unique < 1.5

        ast_plus_20k = (
            'python3 -c "import shutil; x = ' + ("1+" * 20_000) + '1; shutil.rmtree(\'/tmp/work\')"'
        )
        signal.alarm(2)
        try:
            ast_plus_b = safety_floor("bash.exec", {"command": ast_plus_20k})
            ast_plus_p = safety_floor("turn.prompt", {"prompt": ast_plus_20k})
        finally:
            signal.alarm(0)
        assert ast_plus_b == "safety_floor:python_ast_complexity_budget_exceeded"
        assert ast_plus_p == "safety_floor:python_ast_complexity_budget_exceeded"

        # Challenger r20 & Reviewer r20: shared cumulative shell/AST complexity budgets
        vs_32 = " ".join(str(i) for i in range(32))
        r20_budget_cases = (
            (
                "FOR_3LVL_ANSIC",
                f"for x in {vs_32}; do bash -c $'for y in {vs_32}; do bash -c \\'for z in {vs_32}; "
                + 'do bash -c "echo \\$x \\$y \\$z; '
                + ("a;" * 20)
                + "\" ; done\\' ; done'; done",
            ),
            (
                "FOR_2LVL_32x32x500",
                f"for x in {vs_32}; do bash -c 'for y in {vs_32}; do bash -c \"echo $x $y; "
                + ("a;" * 500)
                + "\"; done'; done",
            ),
            (
                "FOR_2LVL_XARGS_BC_200",
                f"for x in {vs_32}; do echo /tmp/w | xargs -I{{}} bash -c $'for y in {vs_32}; "
                + 'do echo /tmp/w | xargs -I{} bash -c "echo \\$x \\$y; '
                + ("echo a;" * 200)
                + "\" ; done'; done",
            ),
            (
                "FOR_2LVL_FIND_EXEC_300",
                f"for x in {vs_32}; do find /tmp/w -exec bash -c 'for y in {vs_32}; "
                + 'do find /tmp/w -exec bash -c "echo $x $y; '
                + ("echo a;" * 300)
                + '" \\; ; done\' \\; ; done',
            ),
            (
                "FOR_BASH_C_32x15K",
                f'for x in {vs_32}; do bash -c "echo $x; ' + ("a;" * 15_000) + '"; done',
            ),
            (
                "MULTI_GRP_XARGS_20x5000",
                ("( " + ("echo ok | " * 5_000) + "cat ) | ") * 20 + "xargs rm -rf",
            ),
        )
        r20_gw = PolicyGateway(
            PolicySet(
                policy_version="2.0",
                rules=(
                    PolicyRule(
                        rule_id="allow-general-write",
                        effect="allow",
                        action_pattern=r"bash\.exec",
                        lanes=(Lane.GENERAL,),
                        max_risk="write",
                    ),
                ),
            )
        )
        for budget_label, budget_cmd in r20_budget_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t_r20 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res_r20 = safety_floor("bash.exec", {"command": budget_cmd})
                    elif call_mode == "turn.prompt":
                        res_r20 = safety_floor("turn.prompt", {"prompt": budget_cmd})
                    else:
                        dec_r20 = r20_gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": budget_cmd},
                            )
                        )
                        assert not dec_r20.allowed, budget_label
                        res_r20 = dec_r20.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t_r20 < 1.8, (budget_label, call_mode)
                assert res_r20 == "safety_floor:shell_complexity_budget_exceeded", (
                    budget_label,
                    call_mode,
                )

        # Nested Python AST recursions must share cumulative _ast_step_budget
        nested_ast_budget_cmd = (
            "python3 -c \"import subprocess; subprocess.run(['python3', '-c', "
            "\\\"import subprocess; subprocess.run(['python3', '-c', "
            "'import subprocess; "
            + ("x=1;" * 6_000)
            + "'])\\\"])\""
        )
        for call_mode in ("bash.exec", "turn.prompt", "decide"):
            signal.alarm(2)
            t_nested_ast = time.monotonic()
            try:
                if call_mode == "bash.exec":
                    res_nested = safety_floor("bash.exec", {"command": nested_ast_budget_cmd})
                elif call_mode == "turn.prompt":
                    res_nested = safety_floor("turn.prompt", {"prompt": nested_ast_budget_cmd})
                else:
                    dec_nested = r20_gw.decide(
                        PolicyRequest(
                            actor_id="u1",
                            actor_role="operator",
                            lane=Lane.GENERAL,
                            tool_id="bash.exec",
                            action_kind="write",
                            arguments={"command": nested_ast_budget_cmd},
                        )
                    )
                    assert not dec_nested.allowed, call_mode
                    res_nested = dec_nested.safety_violation
            finally:
                signal.alarm(0)
            assert time.monotonic() - t_nested_ast < 1.0, call_mode
            assert res_nested == "safety_floor:python_ast_complexity_budget_exceeded", call_mode

        # Safe deep BinOp Python AST (15,007 nodes < 20,000) must remain allowed
        deep_binop_cmd = (
            'python3 -c "import shutil; x = ' + ("1+" * 5_000) + '1; shutil.rmtree(\'/tmp/work\')"'
        )
        signal.alarm(2)
        t_binop = time.monotonic()
        try:
            assert safety_floor("bash.exec", {"command": deep_binop_cmd}) is None
        finally:
            signal.alarm(0)
        assert time.monotonic() - t_binop < 1.0

        # Challenger r21: positional-argument DoS reproducers & sibling loop budgets
        args_300 = " ".join(f"b{i}" for i in range(300))
        args_2k = " ".join(f"b{i}" for i in range(2_000))
        str_5k = "a" * 5_000
        r21_budget_cases = (
            (
                "FOR_2LVL_POSARGS_300",
                f"for x in {vs_32}; do bash -c 'for y in {vs_32}; "
                f'do bash -c "echo $x $y" _ {args_300}; done\' _ a1; done',
            ),
            (
                "FOR_BASH_C_POSARGS_32x2K_5KB",
                f'for x in {vs_32}; do bash -c "echo $x \'{str_5k}\'" _ {args_2k}; done',
            ),
            (
                "FOR_XARGS_POSARGS_32x2K_5KB",
                f"for x in {vs_32}; do echo /tmp/w | xargs -I{{}} bash -c "
                f'"echo $x \'{str_5k}\'" _ {args_2k}; done',
            ),
            (
                "FOR_FIND_EXEC_POSARGS_32x2K_5KB",
                f"for x in {vs_32}; do find /tmp/w -exec bash -c "
                f'"echo $x \'{str_5k}\'" _ {args_2k} \\; ; done',
            ),
        )
        for budget_label, budget_cmd in r21_budget_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t_r21 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res_r21 = safety_floor("bash.exec", {"command": budget_cmd})
                    elif call_mode == "turn.prompt":
                        res_r21 = safety_floor("turn.prompt", {"prompt": budget_cmd})
                    else:
                        dec_r21 = r20_gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": budget_cmd},
                            )
                        )
                        assert not dec_r21.allowed, budget_label
                        res_r21 = dec_r21.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t_r21 < 1.0, (budget_label, call_mode)
                assert res_r21 == "safety_floor:shell_complexity_budget_exceeded", (
                    budget_label,
                    call_mode,
                )

        # Sibling loop-var fanout & large quoted strings must stay fast (< 1.0s)
        for_400_vars_cmd = (
            "; ".join(f"for v{i} in a; do echo $v{i}" for i in range(400)) + ("; done" * 400)
        )
        large_quoted_600kb = "echo '" + ("a " * 300_000) + "'"
        nested_313kb = 'python3 -c "' + (f"'{('echo a; ' * 76)}' " * 512) + '"'
        for fast_label, fast_cmd in (
            ("FOR_400_VARS_400_STAGES", for_400_vars_cmd),
            ("LARGE_QUOTED_600KB", large_quoted_600kb),
            ("NESTED_313KB", nested_313kb),
        ):
            signal.alarm(2)
            t_fast = time.monotonic()
            try:
                assert safety_floor("bash.exec", {"command": fast_cmd}) is None, fast_label
            finally:
                signal.alarm(0)
            assert time.monotonic() - t_fast < 1.0, fast_label

        # Positional-parameter substitution precision controls
        assert (
            safety_floor(
                "bash.exec",
                {"command": "bash -c 'rm -rf \"$10\"' _ a1 a2 a3 a4 a5 a6 a7 a8 a9 /"},
            )
            == "safety_floor:destructive_rm_root_or_glob"
        )
        assert safety_floor("bash.exec", {"command": "bash -c 'echo \"$1\"' _ '$2' /"}) is None
        assert (
            safety_floor("bash.exec", {"command": "bash -c 'rm -rf \"${1:-/}\"'"})
            == "safety_floor:destructive_rm_root_or_glob"
        )
        assert (
            safety_floor("bash.exec", {"command": "bash -c 'rm -rf \"${1:-/}\"' _ /tmp/work"})
            is None
        )

        # Positive & negative controls for normal small `for` + `bash -c` and subshell xargs
        assert (
            safety_floor("bash.exec", {"command": 'for x in a b c; do bash -c "echo $x"; done'})
            is None
        )
        assert (
            safety_floor(
                "bash.exec",
                {"command": 'for x in /tmp/work /; do bash -c "rm -rf $x"; done'},
            )
            == "safety_floor:destructive_rm_root_or_glob"
        )
        assert (
            safety_floor("bash.exec", {"command": "(echo /) | (xargs rm -rf)"})
            == "safety_floor:destructive_rm_root_or_glob"
        )
        assert (
            safety_floor("bash.exec", {"command": "{ echo /; } | { xargs rm -rf; }"})
            == "safety_floor:destructive_rm_root_or_glob"
        )
        for sub_crit_cmd in (
            "(echo /) | (x'a'rgs rm -rf)",
            "{ echo /; } | { x'a'rgs rm -rf; }",
            '(echo /) | (x"a"rgs rm -rf)',
            "(echo /) | (x\\args rm -rf)",
            "(echo /) | (cat | xargs rm -rf)",
            "(echo /) | (cat | grep . | x'a'rgs rm -rf)",
            "(echo /) | (cat | (xargs rm -rf))",
            "(echo /) | ((cat) | xargs rm -rf)",
        ):
            assert (
                safety_floor("bash.exec", {"command": sub_crit_cmd})
                == "safety_floor:destructive_rm_root_or_glob"
            ), sub_crit_cmd
        for sub_safe_cmd in (
            "(echo /) | (echo /tmp/work | xargs rm -rf)",
            "(echo /tmp/work) | (xargs rm -rf)",
            "(echo /) | (echo /tmp/work | cat | xargs rm -rf)",
            "(echo /) | ((echo /tmp/work) | xargs rm -rf)",
        ):
            assert safety_floor("bash.exec", {"command": sub_safe_cmd}) is None, sub_safe_cmd
    finally:
        signal.signal(signal.SIGALRM, prev_budget_handler)

    # PolicyGateway.decide enforces r18 bypass blocks & safe pass-through
    r18_policy = PolicySet(
        policy_version="2.0",
        rules=(
            PolicyRule(
                rule_id="allow-general-write",
                effect="allow",
                action_pattern=r"bash\.exec",
                lanes=(Lane.GENERAL,),
                max_risk="write",
            ),
        ),
    )
    r18_gw = PolicyGateway(r18_policy)
    r18_crit_dec = r18_gw.decide(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="bash.exec",
            action_kind="write",
            arguments={"command": "time if echo / | xargs rm -rf; then :; fi"},
        )
    )
    assert not r18_crit_dec.allowed
    assert r18_crit_dec.safety_violation is not None
    r18_safe_permit = r18_gw.issue_permit(
        tool_id="bash.exec",
        arguments={"command": "time if echo /tmp/work | xargs rm -rf; then :; fi"},
        actor_id="u1",
        session_key="sess-r18",
    )
    r18_safe_dec = r18_gw.decide(
        PolicyRequest(
            actor_id="u1",
            actor_role="operator",
            lane=Lane.GENERAL,
            tool_id="bash.exec",
            action_kind="write",
            arguments={"command": "time if echo /tmp/work | xargs rm -rf; then :; fi"},
            session_id="sess-r18",
            permit_token=r18_safe_permit.permit_id,
        )
    )
    assert r18_safe_dec.allowed
    assert r18_safe_dec.safety_violation is None

    # Raw secret tokens inside nested audit arguments must be redacted
    nested = {
        "nested": [
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            {"slack": "xoxb-123456-789012-secret"},
            {"anthropic": "sk-ant-api03-secretkey999999999999"},
            {"aws": "AKIA1234567890ABCDEF"},
            {"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature123"},
        ]
    }
    sanitized = sanitize_audit_arguments(nested)
    dumped = json.dumps(sanitized)
    assert "ghp_1234567890" not in dumped
    assert "xoxb-123456" not in dumped
    assert "sk-ant-api03" not in dumped
    assert "AKIA1234567890ABCDEF" not in dumped
    assert "eyJhbGciOiJIUzI1NiJ9" not in dumped
    assert sanitized["nested"][0]["redacted"] is True
    assert sanitized["nested"][1]["slack"]["redacted"] is True


@pytest.mark.n1
def test_evidence_airlock_iteration2_leaks_scrubbed_and_blocked() -> None:
    from src.engine.airlock import PublicEquipmentSpec, _has_forbidden_leak

    airlock = EvidenceAirlock()
    res = airlock.project(
        {
            "manufacturer": "Emerson",
            "model": "3144P (P-1 on Linea-3 Area 3)",
            "specs": {
                "power_supply": "sk-ant-api03-secretkey999999999999",
                "protocol": "http://[::1]:8000/admin and fe80::1 and fd00::5",
                "accuracy": "costo interno 1200 USD / internal cost 500 EUR",
                "enclosure": "line voltage 24 VDC in-line filter",
            },
        }
    )
    dumped = json.dumps(res.spec.model_dump(mode="json"))
    assert "sk-ant-api03" not in dumped
    assert "[::1]" not in dumped
    assert "fe80::1" not in dumped
    assert "fd00::5" not in dumped
    assert "1200" not in dumped
    assert "500" not in dumped
    assert "Linea-3" not in dumped
    assert "Area 3" not in dumped
    assert "P-1" not in dumped
    assert "line voltage 24 VDC in-line filter" in dumped

    # _has_forbidden_leak must detect any un-scrubbed internal cost, IPv6, or raw token
    for bad_spec in (
        PublicEquipmentSpec(manufacturer="sk-ant-api03-secretkey999999999999"),
        PublicEquipmentSpec(manufacturer="http://[::1]:8000/admin"),
        PublicEquipmentSpec(manufacturer="fd00::1"),
        PublicEquipmentSpec(manufacturer="costo interno 1200 USD"),
        PublicEquipmentSpec(manufacturer="Linea-3 Area 3 P-1"),
    ):
        assert _has_forbidden_leak(bad_spec, blocked_patterns=()) is not None


@pytest.mark.n1
def test_excel_utf16_xxe_lazy_if_and_cross_column_mixed_currency(tmp_path: Path) -> None:
    import zipfile

    builder = OfficeExcelBuilder()
    verifier = SpreadsheetVerifier()

    # 1. UTF-16LE & UTF-16BE XXE / Billion-Laughs payload rejected
    base_xlsx = tmp_path / "base.xlsx"
    builder.build_workbook(
        [ExcelSheetSpec(name="S1", headers=("A",), rows=((1,),))],
        base_xlsx,
    )
    for enc in ("utf-16", "utf-16-le", "utf-16-be"):
        xxe_xlsx = tmp_path / f"xxe_{enc}.xlsx"
        xxe_xml = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE lolz [<!ENTITY lol "lollol"><!ENTITY lol2 "&lol;&lol;">]>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            "<sheetData><row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>&lol2;</t></is></c>"
            "</row></sheetData></worksheet>"
        ).encode(enc)
        with (
            zipfile.ZipFile(base_xlsx, "r") as zin,
            zipfile.ZipFile(xxe_xlsx, "w") as zout,
        ):
            for item in zin.infolist():
                data = xxe_xml if item.filename == "xl/worksheets/sheet1.xml" else zin.read(
                    item.filename
                )
                zout.writestr(item, data)
        with pytest.raises(ValueError, match="DTD/ENTITY"):
            read_workbook_ooxml(xxe_xlsx)

    # 2. Lazy IF(B2=0, 0, A2/B2) must NOT raise #DIV/0!
    lazy_if_xlsx = tmp_path / "lazy_if.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="S1",
                headers=("A", "B", "SafeDiv"),
                rows=((100, 0, None),),
                formula_cells=(
                    ExcelCellSpec(row=3, col=1, formula="=IF(B2=0, 0, A2/B2)"),
                    ExcelCellSpec(row=3, col=2, formula="=IF(A2>0, A2*2, A2/B2)"),
                ),
            )
        ],
        lazy_if_xlsx,
    )
    rep_if = verifier.verify(lazy_if_xlsx)
    assert rep_if.passed is True
    assert rep_if.verdict == VerdictState.VERIFIED
    assert rep_if.evaluated_values["S1!A3"] == 0
    assert rep_if.evaluated_values["S1!B3"] == 200

    # 3. Cross-column direct reference mixed currency (=A2+B2 with USD + EUR) MUST fail
    cross_cur_xlsx = tmp_path / "cross_currency.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="Costs",
                headers=("USPrice", "EUPrice", "BadTotal"),
                rows=((None, None, None),),
                extra_cells=(
                    ExcelCellSpec(row=2, col=1, value=100, currency="USD"),
                    ExcelCellSpec(row=2, col=2, value=200, currency="EUR"),
                ),
                formula_cells=(ExcelCellSpec(row=2, col=3, formula="=A2+B2"),),
            )
        ],
        cross_cur_xlsx,
    )
    rep_cross = verifier.verify(cross_cur_xlsx)
    assert rep_cross.passed is False
    assert rep_cross.mixed_currencies_detected is True
    assert rep_cross.verdict == VerdictState.CONTRADICTED


@pytest.mark.n1
def test_web_citation_verifier_non_2xx_and_generic_corp_tokens_and_industrial_not_found() -> None:
    verifier = WebCitationVerifier()

    # 1. HTTP 404 page MUST be rejected
    page_404 = WebPageExtract(
        url="https://www.emerson.com/missing",
        final_url="https://www.emerson.com/missing",
        status_code=404,
        title="Not Found",
        text_excerpt="output_signal 4-20 mA",
        is_primary_oem=True,
    )
    rep_404 = verifier.verify(
        manufacturer="Emerson Electric",
        model="3144P",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="output_signal",
                value="4-20 mA",
                source_url="https://www.emerson.com/missing",
            ),
        ),
        fetched_pages=(page_404,),
    )
    assert rep_404.passed is False
    assert rep_404.verdict == VerdictState.CONTRADICTED
    assert any("404" in err for err in rep_404.errors)

    # 2. Generic corporate tokens ("Ltd", "Electric") must NOT match third-party domains
    fake_ltd = WebPageExtract(
        url="https://evil-ltd.com/abb-fake",
        final_url="https://evil-ltd.com/abb-fake",
        status_code=200,
        title="Fake ABB",
        text_excerpt="accuracy 0.1%",
        is_primary_oem=False,
    )
    rep_abb = verifier.verify(
        manufacturer="ABB Ltd",
        model="TZIDC",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="accuracy",
                value="0.1%",
                source_url="https://evil-ltd.com/abb-fake",
            ),
        ),
        fetched_pages=(fake_ltd,),
    )
    assert rep_abb.passed is False
    assert rep_abb.primary_oem_urls == ()

    fake_electric = WebPageExtract(
        url="https://my-electric-blog.com/fake",
        final_url="https://my-electric-blog.com/fake",
        status_code=200,
        title="Blog",
        text_excerpt="accuracy 0.1%",
        is_primary_oem=False,
    )
    rep_emerson = verifier.verify(
        manufacturer="Emerson Electric",
        model="3144P",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="accuracy",
                value="0.1%",
                source_url="https://my-electric-blog.com/fake",
            ),
        ),
        fetched_pages=(fake_electric,),
    )
    assert rep_emerson.passed is False
    assert rep_emerson.primary_oem_urls == ()

    # Subdomain impersonation (abb.attacker.com) must also be rejected while new.abb.com matches
    sub_impersonation = WebPageExtract(
        url="https://abb.attacker.com/ds",
        final_url="https://abb.attacker.com/ds",
        status_code=200,
        title="Evil",
        text_excerpt="accuracy 0.1%",
        is_primary_oem=False,
    )
    rep_sub = verifier.verify(
        manufacturer="ABB Ltd",
        model="TZIDC",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="accuracy",
                value="0.1%",
                source_url="https://abb.attacker.com/ds",
            ),
        ),
        fetched_pages=(sub_impersonation,),
    )
    assert rep_sub.passed is False
    assert verifier._url_matches_manufacturer("https://new.abb.com/ds", "ABB Ltd") is True

    # 3. IndustrialReconciler.reconcile with unknown target_asset_query + unrelated observations
    cfg = _sample_facility()
    ref_time = datetime(2026, 11, 26, 14, 30, tzinfo=UTC)
    task = TaskSpec(
        task_id="t-nf-1",
        user_id="op-1",
        profile_id="p-1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Inspect TT-999Z",
        evidence_requirements=EvidenceRequirements(min_sources=1, max_staleness_seconds=3600.0),
    )
    unrelated_obs = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="SCADA-P34-A1",
        observed_label="Bomba 34",
        value=3.4,
        unit="bar",
        area="area-1",
        source_time=ref_time - timedelta(minutes=1),
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading"},
    )
    rec_nf = IndustrialReconciler().reconcile(
        task=task,
        config=cfg,
        observations=(unrelated_obs,),
        target_asset_query="TT-999Z",
        reference_time=ref_time,
    )
    assert rec_nf.verdict == VerdictState.ASSET_NOT_FOUND
    assert len(rec_nf.nearest_assets) == 3
    assert rec_nf.nearest_assets[0].asset_id == "tt-402b"


@pytest.mark.n1
def test_http_client_origin_validation_and_stream_tool_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.adapters.sessions import OriginNotAllowedError
    from src.model.http_client import (
        LocalHttpModelClient,
        LocalModelConfig,
        validate_local_model_origin,
    )
    from src.model.protocol import BudgetRemaining, ModelProtocolError, PromptContext

    # IMDS link-local (169.254.0.0/16) and fe80::1 must be blocked even with allow_private_lan=True
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://169.254.169.254:80", allow_private_lan=True)
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://[::ffff:169.254.169.254]:80", allow_private_lan=True)
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://[fe80::1]:8080", allow_private_lan=True)
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://[::ffff:8.8.8.8]:8080", allow_private_lan=True)

    # Explicit allowed_origins override permits explicitly pinned link-local origin
    assert (
        validate_local_model_origin(
            "http://169.254.169.254:80",
            allowed_origins=("http://169.254.169.254:80",),
            allow_private_lan=True,
        )
        == "http://169.254.169.254:80"
    )

    # IPv4-mapped loopback [::ffff:127.0.0.1] behaves identically to 127.0.0.1
    assert (
        validate_local_model_origin("http://[::ffff:127.0.0.1]:8080", allow_private_lan=False)
        == "http://[::ffff:127.0.0.1]:8080"
    )
    assert (
        validate_local_model_origin("http://[::ffff:127.0.0.1]:8080", allow_private_lan=True)
        == "http://[::ffff:127.0.0.1]:8080"
    )

    # stream_decide raises ModelProtocolError on malformed tool_call index values
    client = LocalHttpModelClient(
        LocalModelConfig(origin="http://127.0.0.1:8080", model_id="local-test")
    )
    prompt_ctx = PromptContext(
        task_id="t-stream",
        run_id="r-stream",
        depth=0,
        query="hello",
        facility_id="facility-a",
        allowed_areas=("area-1",),
    )
    budget = BudgetRemaining(
        active_children_remaining=1,
        depth_remaining=1,
        tool_calls_remaining=4,
        model_calls_remaining=4,
        wall_seconds_remaining=30.0,
        tokens_remaining=4000,
    )

    real_async_client = httpx.AsyncClient
    for bad_index in ("not-an-int", True, None, -1, 1.5):
        sse_payload = (
            "data: "
            + json.dumps(
                {
                    "model": "local-test",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": bad_index,
                                        "id": "call_0",
                                        "function": {"name": "tool.a", "arguments": "{}"},
                                    }
                                ]
                            },
                        }
                    ],
                }
            )
            + "\n\n"
            + "data: [DONE]\n\n"
        ).encode("utf-8")

        transport = httpx.MockTransport(
            lambda request, body=sse_payload: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=body,
            )
        )
        monkeypatch.setattr(
            httpx,
            "AsyncClient",
            lambda *args, _tr=transport, **kwargs: real_async_client(
                *args, transport=_tr, **kwargs
            ),
        )
        with pytest.raises(ModelProtocolError, match="Invalid SSE tool_call index"):
            asyncio.run(client.stream_decide(prompt_ctx, (), budget))


def test_fast_posix_shlex_split_matches_stdlib() -> None:
    """Differential test confirming _fast_posix_shlex_split matches shlex.split(..., posix=True)."""
    cases = [
        "",
        "   \t\r\n  ",
        "a b c",
        "a\tb\rc\nd",
        "a\x0bb a\x0cc",
        "a|b;c(d)e/f-g_h#i$j",
        "''",
        '""',
        ' "" ',
        " '' ",
        "a''b",
        'a""b',
        "'a\\b'",
        '"a\\b"',
        '"a\\"b"',
        '"a\\\\b"',
        '"a\\\\\\"b"',
        '"a\\$b\\`c\\nd"',
        "a\\ b\\ c",
        "a\\#b #comment",
        "a\\'",
        'a\\"',
        "a'b\"c\"d'e",
        'a"b\'c\'d"e',
        "'multi\nline'",
        '"multi\nline"',
        "unicode_é_ñ 'é ñ' \"é\\\"ñ\"",
        "a\\",
        '"unclosed',
        "'unclosed",
        '"unclosed\\',
        "rm -rf /",
        "echo 'hello world' | xargs -I{} rm -rf {}",
    ]
    for sample in cases:
        try:
            expected_tokens: list[str] | None = shlex.split(sample, posix=True)
            expected_exc: str | None = None
        except ValueError as exc:
            expected_tokens = None
            expected_exc = str(exc)
        try:
            actual_tokens: list[str] | None = _fast_posix_shlex_split(sample)
            actual_exc: str | None = None
        except ValueError as exc:
            actual_tokens = None
            actual_exc = str(exc)
        assert actual_tokens == expected_tokens, sample
        assert actual_exc == expected_exc, sample


@pytest.mark.n1
def test_safety_floor_expanded_char_budget_and_python_flags() -> None:
    """Regression coverage for cumulative expanded-char DoS budget & Python -W/-X -c flags."""
    gw = PolicyGateway(
        PolicySet(
            policy_version="2.0",
            rules=(
                PolicyRule(
                    rule_id="allow-general-write",
                    effect="allow",
                    action_pattern=r"bash\.exec",
                    lanes=(Lane.GENERAL,),
                    max_risk="write",
                ),
            ),
        )
    )

    def _alarm_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SIGALRM 2s")

    prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        vs_32 = " ".join(str(i) for i in range(32))
        amplification_repros = (
            (
                "FOR_2LVL_POS1_2000x2KB",
                f"for x in {vs_32}; do bash -c 'for y in {vs_32}; "
                f'do bash -c "echo $x $y ' + ("$1 " * 2_000) + '" _ ' + ("a" * 2_000)
                + "; done' _ a1; done",
            ),
            (
                "FOR_32_XARGS_AT_1500x1K",
                f"for x in {vs_32}; do echo /tmp/w | xargs bash -c 'echo $x "
                + ("$@ " * 1_500)
                + "' _ "
                + ("a" * 1_000)
                + "; done",
            ),
            (
                "FOR_32_POS1_2Kx10KB_REFX",
                f'for x in {vs_32}; do bash -c "echo $x '
                + ("$1 " * 2_000)
                + '" _ '
                + ("a" * 10_000)
                + "; done",
            ),
            (
                "AT_AMPLIFY_10Kx10K",
                "bash -c 'echo " + ("$@ " * 10_000) + "' _ " + ("a " * 10_000),
            ),
            (
                "XARGS_AT_AMPLIFY_10Kx10K",
                "echo /tmp/w | xargs bash -c 'echo " + ("$@ " * 10_000) + "' _ " + ("a " * 10_000),
            ),
            (
                "FIND_AT_AMPLIFY_10Kx10K",
                "find /tmp/w -exec bash -c 'echo "
                + ("$@ " * 10_000)
                + "' _ "
                + ("a " * 10_000)
                + " \\;",
            ),
            (
                "FOR_LOOPVAR_10Kx10K",
                "for x in " + ("a" * 10_000) + "; do echo " + ("$x " * 10_000) + "; done",
            ),
        )
        for label, cmd in amplification_repros:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert not dec.allowed, (label, call_mode)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res == "safety_floor:shell_complexity_budget_exceeded", (label, call_mode)

        # Benign large controls must remain allowed (< 1.0s)
        benign_controls = (
            ("LARGE_QUOTED_600KB", "echo '" + ("a " * 300_000) + "'"),
            ("NESTED_313KB", 'python3 -c "' + (f"'{('echo a; ' * 76)}' " * 512) + '"'),
            ("PIPE_UNIQUE_30000", " | ".join(f"echo a{i}" for i in range(30_000))),
            (
                "FOR_400_VARS_400_STAGES",
                "; ".join(f"for v{i} in a; do echo $v{i}" for i in range(400)) + ("; done" * 400),
            ),
        )
        for label, cmd in benign_controls:
            signal.alarm(2)
            t0 = time.monotonic()
            try:
                assert safety_floor("bash.exec", {"command": cmd}) is None, label
            finally:
                signal.alarm(0)
            assert time.monotonic() - t0 < 1.0, label
    finally:
        signal.signal(signal.SIGALRM, prev_handler)

    # Challenger r22: Python interpreter argument-taking flags before -c
    py_blocked_payloads = (
        (
            "W_IGNORE_RMTREE",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '-W', 'ignore', '-c', f'import shutil; shutil.rmtree(\\\"{p}\\\")'])\"",
        ),
        (
            "X_UTF8_RMTREE",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '-X', 'utf8', '-c', f'import shutil; shutil.rmtree(\\\"{p}\\\")'])\"",
        ),
        (
            "CHECK_HASH_PYCS_RMTREE",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '--check-hash-based-pycs', 'always', '-c', "
            "f'import shutil; shutil.rmtree(\\\"{p}\\\")'])\"",
        ),
        (
            "WIGNORE_ATTACHED_RMTREE",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '-Wignore', '-c', f'import shutil; shutil.rmtree(\\\"{p}\\\")'])\"",
        ),
        (
            "W_IGNORE_SUBPROC_RM",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '-W', 'ignore', '-c', "
            "f'import subprocess; subprocess.run([\\\"rm\\\", \\\"-rf\\\", \\\"{p}\\\"])'])\"",
        ),
        (
            "X_UTF8_SUBPROC_RM",
            "python3 -c \"import subprocess; p = '/'; subprocess.run("
            "['python3', '-X', 'utf8', '-c', "
            "f'import subprocess; subprocess.run([\\\"rm\\\", \\\"-rf\\\", \\\"{p}\\\"])'])\"",
        ),
    )
    for label, cmd in py_blocked_payloads:
        for mode_tool, args in (
            ("bash.exec", {"command": cmd}),
            ("turn.prompt", {"prompt": cmd}),
        ):
            assert (
                safety_floor(mode_tool, args) == "safety_floor:destructive_rm_root_or_glob"
            ), (label, mode_tool)

    # Benign Python -W/-X controls and script/module boundary controls
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    "python3 -c \"import subprocess; subprocess.run("
                    "['python3', '-W', 'ignore', '-c', 'print(123)'])\""
                )
            },
        )
        is None
    )
    assert (
        safety_floor(
            "bash.exec",
            {
                "command": (
                    "python3 -c \"import subprocess; p = '/'; subprocess.run("
                    "['python3', '-W', 'ignore', 'safe_script.py', '-c', "
                    "f'import shutil; shutil.rmtree(\\\"{p}\\\")'])\""
                )
            },
        )
        is None
    )
    assert (
        _find_python_c_script(["python3", "-W", "ignore", "safe_script.py", "-c", "rm -rf /"])
        == (None, None)
    )
    assert (
        _find_python_c_script(["python3", "-W", "ignore", "-m", "http.server", "-c", "rm -rf /"])
        == (None, None)
    )
    assert (
        _find_sh_c_script_index(["python3", "-W", "ignore", "-c", "print(1)"], is_python=True)
        == 4
    )


@pytest.mark.n1
def test_safety_floor_expanded_subcommand_and_python_stages() -> None:
    """Regression coverage for shell-expanded subcommands & python* -c stages (r23)."""
    gw = PolicyGateway(
        PolicySet(
            policy_version="2.0",
            rules=(
                PolicyRule(
                    rule_id="allow-general-write",
                    effect="allow",
                    action_pattern=r"bash\.exec",
                    lanes=(Lane.GENERAL,),
                    max_risk="write",
                ),
            ),
        )
    )

    def _alarm_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SIGALRM 2s")

    prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        blocked_cases = (
            (
                "BASH_C_POS1_PY_RMTREE",
                'bash -c \'python3 -c "import shutil; shutil.rmtree(\\"$1\\")"\' _ /',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "BASH_C_POS1_PY_RMTREE_VAR",
                'bash -c \'python3 -c "import shutil; p = \\"$1\\"; shutil.rmtree(p)"\' _ /',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "BASH_C_POS1_PY_SUBPROC_RM",
                'bash -c \'python3 -c "import subprocess; '
                'subprocess.run([\\"rm\\", \\"-rf\\", \\"$1\\"])"\' _ /',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "FOR_LOOP_BASHC_PY_RMTREE",
                'for p in /; do bash -c "python3 -c '
                '\\"import shutil; shutil.rmtree(\'$p\')\\""; done',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "FOR_DIRECT_PY_RMTREE",
                'for p in /; do python3 -c "import shutil; shutil.rmtree(\'$p\')"; done',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "XARGS_BASH_C_PY_RMTREE",
                'echo / | xargs bash -c \'python3 -c "import shutil; shutil.rmtree(\\"$1\\")"\' _',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "XARGS_DIRECT_PY_RMTREE",
                'echo / | xargs -I% python3 -c "import shutil; shutil.rmtree(\'%\')"',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "FIND_EXEC_BASH_C_PY_RMTREE",
                'find / -exec bash -c \'python3 -c "import shutil; shutil.rmtree(\\"{}\\")"\' \\;',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "FIND_EXEC_DIRECT_PY_RMTREE",
                'find / -exec python3 -c "import shutil; shutil.rmtree(\'{}\')" \\;',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "BASH_C_POS1_PY_W_IGNORE",
                'bash -c \'python3 -W ignore -c "import shutil; shutil.rmtree(\\"$1\\")"\' _ /',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "SUBPROC_BASH_C_PY_RMTREE",
                "python3 -c \"import subprocess; subprocess.run(['bash', '-c', "
                "'python3 -c \\\"import shutil; shutil.rmtree(\\\\'$1\\\\')\\\"', '_', '/'])\"",
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "BASH_C_POS1_DD",
                "bash -c 'dd if=/dev/zero of=\"$1\"' _ /dev/sda",
                "safety_floor:destructive_dd_device",
            ),
            (
                "BASH_C_POS1_GIT_FORCE",
                "bash -c 'git push \"$1\" origin main' _ --force",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "BASH_C_POS1_SQL_DROP",
                "bash -c 'psql -c \"DROP $1 users\"' _ TABLE",
                "safety_floor:destructive_sql_drop_truncate",
            ),
            (
                "FOR_DD",
                'for p in /dev/sda; do dd if=/dev/zero of="$p"; done',
                "safety_floor:destructive_dd_device",
            ),
            (
                "FOR_GIT_FORCE",
                'for f in --force; do git push "$f" origin main; done',
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "FOR_SQL_DROP",
                'for t in TABLE; do psql -c "DROP $t users"; done',
                "safety_floor:destructive_sql_drop_truncate",
            ),
            (
                "FOR_MKFS",
                'for m in mkfs.ext4; do "$m" /dev/sda; done',
                "safety_floor:destructive_disk_format",
            ),
            (
                "FOR_CHMOD_777",
                'for p in /; do chmod -R 777 "$p"; done',
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "XARGS_DD",
                "echo /dev/sda | xargs -I% dd if=/dev/zero of=%",
                "safety_floor:destructive_dd_device",
            ),
            (
                "XARGS_GIT_FORCE",
                "echo --force | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_SQL_DROP",
                'echo TABLE | xargs -I% psql -c "DROP % users"',
                "safety_floor:destructive_sql_drop_truncate",
            ),
            (
                "XARGS_CHMOD_777",
                "echo / | xargs -I% chmod -R 777 %",
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "FIND_DD",
                "find /dev/sda -exec dd if=/dev/zero of={} \\;",
                "safety_floor:destructive_dd_device",
            ),
            (
                "FIND_CHMOD_777",
                "find / -exec chmod -R 777 {} \\;",
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "ENV_PY_BASH_C",
                'bash -c \'env python3 -W ignore -c "import shutil; shutil.rmtree(\\"$1\\")"\' _ /',
                "safety_floor:destructive_rm_root_or_glob",
            ),
        )
        for label, cmd, expected_violation in blocked_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert not dec.allowed, (label, call_mode)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res == expected_violation, (label, call_mode, res)

        benign_cases = (
            (
                "BENIGN_BASH_C_PY_RMTREE",
                'bash -c \'python3 -c "import shutil; shutil.rmtree(\\"$1\\")"\' _ /tmp/work',
            ),
            (
                "BENIGN_FOR_PY_RMTREE",
                'for p in /tmp/work; do python3 -c "import shutil; shutil.rmtree(\'$p\')"; done',
            ),
            (
                "BENIGN_XARGS_PY_RMTREE",
                'echo /tmp/work | xargs -I% python3 -c "import shutil; shutil.rmtree(\'%\')"',
            ),
            (
                "BENIGN_FIND_PY_RMTREE",
                'find /tmp/work -exec python3 -c "import shutil; shutil.rmtree(\'{}\')" \\;',
            ),
            ("BENIGN_BASH_C_GIT_STATUS", "bash -c 'git \"$1\"' _ status"),
            ("BENIGN_FOR_DD", 'for p in /tmp/work/out.img; do dd if=/dev/zero of="$p"; done'),
            ("BENIGN_XARGS_GIT_STATUS", "echo status | xargs -I% git %"),
            ("BENIGN_FOR_SQL_SELECT", 'for t in SELECT; do psql -c "$t * FROM users"; done'),
        )
        for label, cmd in benign_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert dec.allowed, (label, call_mode, dec)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res is None, (label, call_mode, res)
    finally:
        signal.signal(signal.SIGALRM, prev_handler)


@pytest.mark.n1
def test_safety_floor_depth_fail_closed_printf_passthrough_and_chmod_modes() -> None:
    """Regression coverage for r24 depth fail-closed, printf/group xargs, and chmod modes."""
    gw = PolicyGateway(
        PolicySet(
            policy_version="2.0",
            rules=(
                PolicyRule(
                    rule_id="allow-general-write",
                    effect="allow",
                    action_pattern=r"bash\.exec",
                    lanes=(Lane.GENERAL,),
                    max_risk="write",
                ),
            ),
        )
    )

    py5 = "import shutil; shutil.rmtree('/')"
    for _ in range(4):
        py5 = f"import subprocess; subprocess.run(['python3', '-c', {py5!r}])"
    cmd_py5 = f"python3 -c {shlex.quote(py5)}"

    py6 = "import shutil; shutil.rmtree('/')"
    for _ in range(5):
        py6 = f"import subprocess; subprocess.run(['python3', '-c', {py6!r}])"
    cmd_py6 = f"python3 -c {shlex.quote(py6)}"

    alt = "import shutil; shutil.rmtree('/')"
    for _ in range(3):
        alt_cmd = f"python3 -c {shlex.quote(alt)}"
        alt = f"import subprocess; subprocess.run(['bash', '-c', {alt_cmd!r}])"
    cmd_alt6 = f"python3 -c {shlex.quote(alt)}"

    py4_benign = "print(1)"
    for _ in range(3):
        py4_benign = f"import subprocess; subprocess.run(['python3', '-c', {py4_benign!r}])"
    cmd_py4_benign = f"python3 -c {shlex.quote(py4_benign)}"

    def _alarm_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SIGALRM 2s")

    prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        blocked_cases = (
            (
                "AST_DEPTH_5_PY_RMTREE",
                cmd_py5,
                "safety_floor:python_ast_complexity_budget_exceeded",
            ),
            (
                "AST_DEPTH_6",
                cmd_py6,
                "safety_floor:python_ast_complexity_budget_exceeded",
            ),
            (
                "ALT_6",
                cmd_alt6,
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_PRINTF_FMT_SPLIT_RMTREE",
                r"printf '/%s\n' '' | xargs -I% python3 -c "
                + '"import shutil; shutil.rmtree(\'%\')"',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "XARGS_PRINTF_FMT_ETC_RMTREE",
                r"printf '/%s\n' etc | xargs -I% python3 -c "
                + '"import shutil; shutil.rmtree(\'%\')"',
                "safety_floor:destructive_rm_root_or_glob",
            ),
            (
                "XARGS_PRINTF_FMT_SPLIT_DD",
                r"printf '/dev/%s\n' sda | xargs -I% dd if=/dev/zero of=%",
                "safety_floor:destructive_dd_device",
            ),
            (
                "XARGS_PRINTF_MULTILINE_GIT",
                r"printf '%s\n' status --force | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_ECHO_E_MULTILINE_GIT",
                r"echo -e 'status\n--force' | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_PRINTF_DASHDASH_GIT_FORCE",
                r"printf -- '%s\n' --force | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_CAT_GIT_FORCE",
                "echo --force | cat | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_SUBSHELL_GIT_FORCE",
                "(echo --force) | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_BRACE_GIT_FORCE",
                "{ echo --force; } | xargs -I% git push % origin main",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_CAT_SQL_DROP",
                'echo TABLE | cat | xargs -I% psql -c "DROP % users"',
                "safety_floor:destructive_sql_drop_truncate",
            ),
            (
                "XARGS_SUBSHELL_BASH_C_GIT",
                '(echo --force) | xargs bash -c \'git push "$1" origin main\' _',
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "XARGS_SUBSHELL_CAT_GIT_FORCE",
                "(echo --force) | (cat | xargs -I% git push % origin main)",
                "safety_floor:destructive_db_or_git_wipe",
            ),
            (
                "CHMOD_4777",
                'for p in /; do chmod -R 4777 "$p"; done',
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "CHMOD_UGOA",
                'for p in /; do chmod -R ugo+rwx "$p"; done',
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "CHMOD_COMMA",
                'for p in /; do chmod -R u+rwx,g+rwx,o+rwx "$p"; done',
                "safety_floor:destructive_chmod_777_root",
            ),
            (
                "CHMOD_DIRECT_4777",
                "chmod -R 4777 /",
                "safety_floor:destructive_chmod_777_root",
            ),
        )
        for label, cmd, expected_violation in blocked_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert not dec.allowed, (label, call_mode)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res == expected_violation, (label, call_mode, res)

        benign_cases = (
            ("BENIGN_CAT_GIT_STATUS", "echo status | cat | xargs -I% git push % origin main"),
            ("BENIGN_SUBSHELL_GIT_STATUS", "(echo status) | xargs -I% git push % origin main"),
            (
                "BENIGN_BRACE_PY_RMTREE",
                '{ echo /tmp/work; } | xargs -I% python3 -c "import shutil; shutil.rmtree(\'%\')"',
            ),
            ("BENIGN_CHMOD_755_ROOT", "chmod -R 755 /"),
            ("BENIGN_CHMOD_644_TMP", "chmod 644 /tmp/file"),
            (
                "BENIGN_PRINTF_MULTILINE_GIT_INFO",
                r"printf '%s\n' status info | xargs -I% git push % origin main",
            ),
            ("BENIGN_PY_4LVL", cmd_py4_benign),
            (
                "BENIGN_BASH_3LVL",
                'bash -c "bash -c \'bash -c \\"echo ok\\"\'"',
            ),
        )
        for label, cmd in benign_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert dec.allowed, (label, call_mode, dec)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res is None, (label, call_mode, res)
    finally:
        signal.signal(signal.SIGALRM, prev_handler)


@pytest.mark.n1
def test_safety_floor_xargs_rm_rf_unsupported_and_64_truncation_fail_closed() -> None:
    """Regression coverage for r25 xargs rm -rf echo_unsupported & 64-item truncation fixes."""
    gw = PolicyGateway(
        PolicySet(
            policy_version="2.0",
            rules=(
                PolicyRule(
                    rule_id="allow-general-write",
                    effect="allow",
                    action_pattern=r"bash\.exec",
                    lanes=(Lane.GENERAL,),
                    max_risk="write",
                ),
            ),
        )
    )

    a65 = " ".join(f"a{i}" for i in range(65))
    a64 = " ".join(f"a{i}" for i in range(64))
    a63 = " ".join(f"a{i}" for i in range(63))
    a128 = " ".join(f"a{i}" for i in range(128))
    nl65 = "\\n".join(f"a{i}" for i in range(65))

    def _alarm_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SIGALRM 2s")

    prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        blocked_cases = (
            (
                "XARGS_RM_RF_PRINTF_TIME",
                r"printf '%(%Y)T\n' | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_PRINTF_TRAIL_PCT",
                r"printf '%\n' | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_PRINTF_STAR_SAFE",
                r"printf '%*s\n' 1 safe | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_SUBSHELL_PRINTF_TIME",
                r"(printf '%(%Y)T\n') | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_CAT_PRINTF_TIME",
                r"printf '%(%Y)T\n' | cat | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_I_RM_RF_PRINTF_TIME",
                r"printf '%(%Y)T\n' | xargs -I% rm -rf %",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_PRINTF_65_ARGS_GIT_FORCE",
                f"printf '%s\\n' {a65} --force | xargs -I% git push % origin main",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_ECHO_65_LINES_GIT_FORCE",
                f"echo -e '{nl65}\\n--force' | xargs -I% git push % origin main",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_PRINTF_65_ARGS_RM_RF",
                f"printf '%s\\n' {a65} / | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_ECHO_65_LINES_RM_RF",
                f"echo -e '{nl65}\\n/' | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_ECHO_65_WORDS_GIT_FORCE",
                f"echo {a65} --force | xargs git push",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_SUBSHELL_CAT_PRINTF_TIME",
                r"(printf '%(%Y)T\n') | (cat | xargs rm -rf)",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_RM_RF_OBFUS_SUBSHELL_PRINTF_TIME",
                r"(printf '%(%Y)T\n') | (x'a'rgs rm -rf)",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_SUBSHELL_PRINTF_65_GIT_FORCE",
                f"(printf '%s\\n' {a65} --force) | xargs -I% git push % origin main",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_BRACE_CAT_PRINTF_65_RM_RF",
                f"{{ printf '%s\\n' {a65} /; }} | cat | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_GROUP_SIBLING_OVER_64_GIT_FORCE",
                f"((printf '%s\\n' {a64}); (echo --force)) | xargs -I% git push % origin main",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_PRINTF_128_WORDS_RM_RF",
                f"printf '%s %s\\n' {a128} | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_PRINTF_B_65_LINES_RM_RF",
                f"printf '%b\\n' '{nl65}\\n/' | xargs rm -rf",
                "safety_floor:shell_complexity_budget_exceeded",
            ),
            (
                "XARGS_I_RM_RF_PREFIX_ETC",
                "echo etc | xargs -I% rm -rf /%",
                "safety_floor:destructive_rm_root_or_glob",
            ),
        )
        for label, cmd, expected_violation in blocked_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert not dec.allowed, (label, call_mode)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res == expected_violation, (label, call_mode, res)

        benign_cases = (
            ("BENIGN_PRINTF_65_LS", f"printf '%s\\n' {a65} | xargs ls"),
            ("BENIGN_PRINTF_STAR_LS", r"printf '%*s\n' 1 ok | xargs ls"),
            ("BENIGN_ECHO_TMP_RM_RF", "echo /tmp/work | xargs rm -rf"),
            ("BENIGN_PRINTF_64_TMP_RM_RF", f"printf '%s\\n' {a63} /tmp/work | xargs rm -rf"),
            (
                "BENIGN_BRACE_PRINTF_64_TMP_RM_RF",
                f"{{ printf '%s\\n' {a63} /tmp/work; }} | xargs rm -rf",
            ),
            ("BENIGN_ECHO_65_WC", f"echo {a65} | xargs wc -l"),
            (
                "BENIGN_SUBSHELL_OVERRIDE_RM_RF",
                "(echo /) | (echo /tmp/work | cat | xargs rm -rf)",
            ),
            ("BENIGN_PRINTF_128_WORDS_LS", f"printf '%s %s\\n' {a128} | xargs ls"),
        )
        for label, cmd in benign_cases:
            for call_mode in ("bash.exec", "turn.prompt", "decide"):
                signal.alarm(2)
                t0 = time.monotonic()
                try:
                    if call_mode == "bash.exec":
                        res = safety_floor("bash.exec", {"command": cmd})
                    elif call_mode == "turn.prompt":
                        res = safety_floor("turn.prompt", {"prompt": cmd})
                    else:
                        dec = gw.decide(
                            PolicyRequest(
                                actor_id="u1",
                                actor_role="operator",
                                lane=Lane.GENERAL,
                                tool_id="bash.exec",
                                action_kind="write",
                                arguments={"command": cmd},
                            )
                        )
                        assert dec.allowed, (label, call_mode, dec)
                        res = dec.safety_violation
                finally:
                    signal.alarm(0)
                assert time.monotonic() - t0 < 1.0, (label, call_mode)
                assert res is None, (label, call_mode, res)
    finally:
        signal.signal(signal.SIGALRM, prev_handler)


@pytest.mark.n1
async def test_lane_router_bare_number_revisa_el_34_needs_clarification() -> None:
    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    router = LaneRouter()

    d_bare = await router.route("revisa el 34", facility_config=cfg)
    assert d_bare.needs_clarification is True
    assert d_bare.verdict_override == VerdictState.NEEDS_CLARIFICATION
    assert [c.asset_id for c in d_bare.clarification_candidates] == ["bomba-34-a1"]

    d_area = await router.route("revisa el 34 en area-1", facility_config=cfg)
    assert d_area.lane == Lane.INDUSTRIAL
    assert d_area.needs_clarification is False

    d_noun = await router.route("bomba 34", facility_config=cfg)
    assert d_noun.lane == Lane.INDUSTRIAL
    assert d_noun.needs_clarification is False

