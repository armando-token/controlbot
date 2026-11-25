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
    assert len(contradictions) == 1
    assert contradictions[0].unresolved is True
    assert "SC-77" in contradictions[0].summary
    assert all(c.asset_id == "SC-77" for c in contradictions[0].claims)

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
