"""Unit tests for Verifier source_ids canonicalization and A12 portability helpers."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from src.adapters.config import load_facility_config
from src.adapters.verifier import Verifier
from src.contracts.common import utc_now
from src.contracts.enums import DataQuality, TaskStatus
from src.contracts.models import Observation, TaskScope, TaskSpec
from src.runtime import _infer_asset_query

_FACILITY_B_PATH = Path("lab/configs/facility_b.json")


def _make_obs(
    *,
    source: str,
    asset_id: str,
    observed_label: str = "bomba 77",
    area: str = "area-2",
    record_type: str = "alarm",
    record_id: str = "ALM-7701",
    value: str | float = "SEAL_TEMP_HIGH",
    unit: str = "alarm_code",
) -> Observation:
    now = utc_now()
    return Observation(
        source=source,
        session_id=f"operator_b__p1__{source}",
        asset_id=asset_id,
        observed_label=observed_label,
        value=value,
        unit=unit,
        source_time=now - timedelta(minutes=10),
        observed_at=now,
        quality=DataQuality.GOOD,
        authorized_evidence=True,
        area=area,
        metadata={"record_type": record_type, "record_id": record_id, "order_id": record_id},
    )


@pytest.mark.n1
def test_canonical_source_ids_do_not_false_contradict() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    scada_alarm = _make_obs(source="scada", asset_id="SC-77", record_type="alarm")
    scada_reading = _make_obs(
        source="scada",
        asset_id="SC-77",
        record_type="reading",
        record_id="RDG-7701",
        value=6.8,
        unit="mm/s",
    )
    maint_wo = _make_obs(
        source="maintenance",
        asset_id="CMMS-77",
        record_type="work_order",
        record_id="WO-7705",
        value="Replaced mechanical seal",
        unit="event",
    )

    contradictions = verifier.detect_contradictions([scada_alarm, scada_reading, maint_wo], cfg)
    assert contradictions == ()

    task = TaskSpec(
        task_id="t-canon-ok",
        user_id="operator_b",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-2",), read_only=True),
        query="Check P-77B status",
    )
    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[scada_alarm, scada_reading, maint_wo],
        target_asset_query="P-77B",
        target_area="area-2",
    )
    assert res.status == TaskStatus.SUCCEEDED
    assert res.contradictions == ()
    assert "ALM-7701" in res.answer
    assert "WO-7705" in res.answer


@pytest.mark.n1
def test_wrong_source_id_still_triggers_contradiction() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    scada_alarm = _make_obs(source="scada", asset_id="SC-77", record_type="alarm")
    # maintenance mistakenly emits SCADA's SC-77 instead of CMMS-77
    maint_wrong_src = _make_obs(
        source="maintenance",
        asset_id="SC-77",
        record_type="work_order",
        record_id="WO-7799",
        value="Misattributed maintenance record",
        unit="event",
    )

    contradictions = verifier.detect_contradictions([scada_alarm, maint_wrong_src], cfg)
    assert len(contradictions) >= 1
    assert all(c.unresolved is True for c in contradictions)
    assert any("SC-77" in c.summary for c in contradictions)
    assert any(
        c.source == "maintenance" and c.asset_id == "SC-77"
        for rec in contradictions
        for c in rec.claims
    )

    task = TaskSpec(
        task_id="t-wrong-src",
        user_id="operator_b",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-2",), read_only=True),
        query="Check bomba 77",
    )
    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[scada_alarm, maint_wrong_src],
        target_asset_query="bomba 77",
        target_area="area-2",
    )
    assert res.status == TaskStatus.PARTIAL
    assert len(res.contradictions) >= 1


@pytest.mark.n1
def test_solo_wrong_source_id_and_invalid_unit_caught_without_sibling_source() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    maint_wrong_src = _make_obs(
        source="maintenance",
        asset_id="SC-77",
        record_type="work_order",
        record_id="WO-7799",
        value="Misattributed solo maintenance record",
        unit="event",
    )

    contradictions = verifier.detect_contradictions([maint_wrong_src], cfg)
    assert len(contradictions) == 1
    assert contradictions[0].unresolved is True
    assert "SC-77" in contradictions[0].summary
    assert {c.source for c in contradictions[0].claims} == {"facility_config", "maintenance"}

    task = TaskSpec(
        task_id="t-solo-wrong-src",
        user_id="operator_b",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-2",), read_only=True),
        query="Check bomba 77",
    )
    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[maint_wrong_src],
        target_asset_query="bomba 77",
        target_area="area-2",
    )
    assert res.status == TaskStatus.PARTIAL
    assert len(res.contradictions) == 1

    # Wrong-source ID with an invalid unit still enforces mapped asset's allowed_units
    maint_bad_unit = _make_obs(
        source="maintenance",
        asset_id="SC-77",
        record_type="work_order",
        record_id="WO-7798",
        value="Bad unit record",
        unit="psi",
    )
    verified_bad = verifier.verify_observation(
        maint_bad_unit,
        task.evidence_requirements,
        config=cfg,
    )
    assert verified_bad.authorized_evidence is False
    assert "unit_mismatch:psi" in verified_bad.metadata.get("rejection_reasons", [])


@pytest.mark.n1
def test_area_mismatch_against_config_triggers_contradiction() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    scada_wrong_area = _make_obs(
        source="scada",
        asset_id="SC-77",
        area="area-3",
        record_type="alarm",
        record_id="ALM-7799",
    )

    contradictions = verifier.detect_contradictions([scada_wrong_area], cfg)
    assert len(contradictions) == 1
    assert contradictions[0].unresolved is True
    assert "area-3" in contradictions[0].summary
    assert "area-2" in contradictions[0].summary
    assert {c.source for c in contradictions[0].claims} == {"facility_config", "scada"}

    task = TaskSpec(
        task_id="t-area-mismatch",
        user_id="operator_b",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-3",), read_only=True),
        query="Check bomba 77",
    )
    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[scada_wrong_area],
        target_asset_query="bomba 77",
        target_area="area-3",
    )
    assert res.status == TaskStatus.PARTIAL
    assert len(res.contradictions) == 1


@pytest.mark.n1
def test_unmapped_id_triggers_contradiction_preserving_raw_asset_id() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    scada_alarm = _make_obs(source="scada", asset_id="SC-77", record_type="alarm")
    maint_unknown = _make_obs(
        source="maintenance",
        asset_id="CMMS-99",
        record_type="work_order",
        record_id="WO-9901",
        value="Unknown pump repair",
        unit="event",
    )

    contradictions = verifier.detect_contradictions([scada_alarm, maint_unknown], cfg)
    assert len(contradictions) == 1
    assert "CMMS-99" in contradictions[0].summary
    claim_ids = {c.asset_id for c in contradictions[0].claims}
    assert claim_ids == {"SC-77", "CMMS-99"}


@pytest.mark.n1
def test_detect_ambiguity_deduplicates_canonical_asset_across_sources() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    scada_alarm = _make_obs(source="scada", asset_id="SC-77", record_type="alarm")
    maint_wo = _make_obs(
        source="maintenance",
        asset_id="CMMS-77",
        record_type="work_order",
        record_id="WO-7705",
        value="Seal work",
        unit="event",
    )
    is_amb, distinct, action = verifier.detect_ambiguity(
        [scada_alarm, maint_wo],
        cfg,
        target_asset_query="bomba 77",
        target_area=None,
    )
    assert is_amb is False
    assert action is None
    assert distinct == [("bomba-77-b2", "area-2")]


@pytest.mark.n1
def test_infer_asset_query_resolves_source_ids() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    assert _infer_asset_query("Inspect SC-77 alarms", cfg) == "SC-77"
    assert _infer_asset_query("Check CMMS-77 maintenance", cfg) == "CMMS-77"
    assert _infer_asset_query("Check P-77B status", cfg) == "P-77B"


@pytest.mark.n1
def test_solo_unconfigured_asset_id_triggers_contradiction_and_unit_check() -> None:
    cfg = load_facility_config(_FACILITY_B_PATH)
    verifier = Verifier()
    solo_bogus = _make_obs(
        source="maintenance",
        asset_id="BOGUS-99",
        observed_label="bomba 77",
        area="area-2",
        record_type="reading",
        record_id="RDG-9901",
        value=42.0,
        unit="psi",
    )
    contradictions = verifier.detect_contradictions([solo_bogus], cfg)
    assert len(contradictions) == 1
    assert contradictions[0].unresolved is True
    assert "BOGUS-99" in contradictions[0].summary

    task = TaskSpec(
        task_id="t-solo-bogus",
        user_id="operator_b",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-2",), read_only=True),
        query="Check bomba 77",
    )
    verified = verifier.verify_observation(solo_bogus, task.evidence_requirements, config=cfg)
    assert verified.authorized_evidence is False
    assert "unit_mismatch:psi" in verified.metadata.get("rejection_reasons", [])

    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[solo_bogus],
        target_asset_query="bomba 77",
        target_area="area-2",
    )
    assert res.status == TaskStatus.PARTIAL
    assert len(res.contradictions) == 1


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_04_verifier_enforces_min_sources() -> None:
    from src.contracts.models import EvidenceRequirements

    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    verifier = Verifier()
    scada_alarm = _make_obs(
        source="scada",
        asset_id="bomba-34-a1",
        observed_label="bomba 34",
        area="area-1",
        record_type="alarm",
        record_id="ALM-3401",
        value="HIGH_VIBRATION",
        unit="alarm_code",
    )

    task_fail = TaskSpec(
        task_id="t-min-src-fail",
        user_id="operator_ro",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Check bomba 34",
        evidence_requirements=EvidenceRequirements(
            min_sources=2,
            allow_partial_on_source_failure=False,
        ),
    )
    res_fail = verifier.verify_and_synthesize(
        task=task_fail,
        config=cfg,
        observations=[scada_alarm],
        source_errors={},
        target_asset_query="bomba 34",
        target_area="area-1",
    )
    assert res_fail.status == TaskStatus.FAILED
    assert res_fail.partial_info is not None
    assert res_fail.partial_info["min_sources"] == 2
    assert res_fail.partial_info["available_sources"] == ["scada"]
    assert "min_sources=2" in res_fail.answer

    task_partial = task_fail.model_copy(
        update={
            "evidence_requirements": EvidenceRequirements(
                min_sources=2,
                allow_partial_on_source_failure=True,
            )
        }
    )
    res_partial = verifier.verify_and_synthesize(
        task=task_partial,
        config=cfg,
        observations=[scada_alarm],
        source_errors={},
        target_asset_query="bomba 34",
        target_area="area-1",
    )
    assert res_partial.status == TaskStatus.PARTIAL
    assert res_partial.partial_info is not None
    assert res_partial.partial_info["min_sources"] == 2
    assert res_partial.partial_info["available_sources"] == ["scada"]


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_05_verifier_flags_paired_unconfigured_asset_id() -> None:
    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    verifier = Verifier()
    scada_bogus = _make_obs(
        source="scada",
        asset_id="BOGUS-99",
        observed_label="bomba 34",
        area="area-1",
        record_type="alarm",
        record_id="ALM-9901",
        value="HIGH_VIBRATION",
        unit="alarm_code",
    )
    maint_bogus = _make_obs(
        source="maintenance",
        asset_id="BOGUS-99",
        observed_label="bomba 34",
        area="area-1",
        record_type="work_order",
        record_id="WO-9901",
        value="Seal replaced",
        unit="event",
    )
    task = TaskSpec(
        task_id="t-paired-bogus",
        user_id="operator_ro",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Check bomba 34",
    )
    res = verifier.verify_and_synthesize(
        task=task,
        config=cfg,
        observations=[scada_bogus, maint_bogus],
        target_asset_query="bomba 34",
        target_area="area-1",
    )
    assert len(res.contradictions) >= 1
    assert res.status != TaskStatus.SUCCEEDED
    assert any("BOGUS-99" in c.summary for c in res.contradictions)
