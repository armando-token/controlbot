"""Independent deterministic industrial observation and synthesis verifier."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from src.adapters.config import AssetMapping, FacilityConfig, resolve_asset_candidates
from src.contracts.common import ensure_utc, utc_now
from src.contracts.enums import DataQuality, TaskStatus
from src.contracts.models import (
    ContradictionClaim,
    ContradictionRecord,
    EvidenceRequirements,
    ExecutionMetrics,
    Observation,
    Result,
    TaskSpec,
)

_VALID_QUALITIES: frozenset[DataQuality] = frozenset({DataQuality.GOOD, DataQuality.UNCERTAIN})


def _flat_allowed_units(mapping: AssetMapping) -> set[str]:
    units: set[str] = set()
    for group in mapping.allowed_units.values():
        units.update(group)
    return units


def _resolve_asset_mapping(obs: Observation, config: FacilityConfig) -> AssetMapping | None:
    """Resolve an Observation's (source, asset_id) to its canonical AssetMapping.

    Precedence:
    1. Exact per-source mapping: ``asset.source_ids.get(obs.source) == obs.asset_id``.
    2. Canonical asset_id match: ``asset.asset_id == obs.asset_id``.
    3. Fallback across ``asset.source_ids.values()`` ONLY when ``obs.source`` has no
       explicit mapping in ``asset.source_ids`` (preventing wrong-source ID aliasing).
    """
    for asset in config.assets:
        if asset.source_ids.get(obs.source) == obs.asset_id:
            return asset
    for asset in config.assets:
        if asset.asset_id == obs.asset_id:
            return asset
    for asset in config.assets:
        if obs.source not in asset.source_ids and obs.asset_id in asset.source_ids.values():
            return asset
    return None


def _canonical_asset_id(obs: Observation, config: FacilityConfig) -> str:
    """Return canonical asset_id if resolved for obs.source, else raw obs.asset_id."""
    mapped = _resolve_asset_mapping(obs, config)
    return mapped.asset_id if mapped is not None else obs.asset_id


def _matches_asset_query(obs: Observation, query: str, config: FacilityConfig) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    if needle in obs.asset_id.lower() or needle in obs.observed_label.lower():
        return True
    for mapping in resolve_asset_candidates(config, query):
        if (
            obs.asset_id == mapping.asset_id
            or obs.asset_id in mapping.source_ids.values()
            or obs.observed_label.strip().lower() == mapping.canonical_label.lower()
        ):
            return True
    return False


class Verifier:
    """Deterministic independent verifier for industrial observations (A01-A04, A13)."""

    def verify_observation(
        self,
        obs: Observation,
        requirements: EvidenceRequirements,
        *,
        config: FacilityConfig | None = None,
        allowed_units: Sequence[str] | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        reference_time: datetime | None = None,
    ) -> Observation:
        """Validate quality, source_time, staleness, time window, and unit for one Observation."""
        ref_utc = ensure_utc(reference_time) if reference_time is not None else utc_now()
        rejection_reasons: list[str] = []

        if requirements.require_quality_check and obs.quality not in _VALID_QUALITIES:
            rejection_reasons.append(f"quality:{obs.quality.value}")

        if requirements.require_source_timestamp and obs.source_time is None:
            rejection_reasons.append("missing_source_time")

        if obs.source_time is not None:
            src_time = ensure_utc(obs.source_time)
            if requirements.max_staleness_seconds is not None:
                age_s = (ref_utc - src_time).total_seconds()
                if age_s > requirements.max_staleness_seconds and obs.metadata.get(
                    "record_type"
                ) == "reading":
                    rejection_reasons.append(
                        f"stale_reading:{round(age_s, 1)}s>{requirements.max_staleness_seconds}s"
                    )
            if window_start is not None and src_time < ensure_utc(window_start):
                rejection_reasons.append("out_of_window_before_start")
            if window_end is not None and src_time > ensure_utc(window_end):
                rejection_reasons.append("out_of_window_after_end")

        effective_units: set[str] | None = set(allowed_units) if allowed_units is not None else None
        if effective_units is None and config is not None:
            mapped_asset = _resolve_asset_mapping(obs, config)
            if mapped_asset is not None:
                record_type = str(obs.metadata.get("record_type", ""))
                if record_type in mapped_asset.allowed_units:
                    effective_units = set(mapped_asset.allowed_units[record_type])
                else:
                    effective_units = _flat_allowed_units(mapped_asset)

        if effective_units:
            if obs.unit is None and obs.metadata.get("record_type") == "reading":
                rejection_reasons.append("missing_unit")
            elif obs.unit is not None and obs.unit not in effective_units:
                rejection_reasons.append(f"unit_mismatch:{obs.unit}")

        authorized = len(rejection_reasons) == 0
        updated_meta = dict(obs.metadata)
        if rejection_reasons:
            updated_meta["rejection_reasons"] = rejection_reasons
        return obs.model_copy(
            update={
                "authorized_evidence": authorized,
                "metadata": updated_meta,
            }
        )

    def detect_ambiguity(
        self,
        observations: Sequence[Observation],
        config: FacilityConfig,
        *,
        target_asset_query: str,
        target_area: str | None = None,
    ) -> tuple[bool, list[tuple[str, str | None]], str | None]:
        """Detect >=2 distinct (asset_id, area) candidates matching the query when unscoped."""
        if target_area is not None:
            return False, [], None

        candidates: dict[tuple[str, str | None], None] = {}
        for obs in observations:
            if _matches_asset_query(obs, target_asset_query, config):
                candidates[(_canonical_asset_id(obs, config), obs.area)] = None

        for mapping in resolve_asset_candidates(config, target_asset_query):
            candidates[(mapping.asset_id, mapping.area)] = None

        distinct = list(candidates.keys())
        distinct_areas = {area for _, area in distinct if area is not None}
        if len(distinct) >= 2 and len(distinct_areas) >= 2:
            options = ", ".join(
                f"{area or 'unknown-area'} ({asset_id})" for asset_id, area in distinct
            )
            required_action = (
                f"Ambiguous asset {target_asset_query!r} across multiple areas; "
                f"specify area or asset_id: {options}"
            )
            return True, distinct, required_action
        return False, distinct, None

    def detect_contradictions(
        self,
        observations: Sequence[Observation],
        config: FacilityConfig,
    ) -> tuple[ContradictionRecord, ...]:
        """Detect intra-record label/ID mismatches, intra-source, and cross-source conflicts."""
        contradictions: list[ContradictionRecord] = []

        # 1. Intra-record contradictions against FacilityConfig canonical assets
        asset_by_id: dict[str, AssetMapping] = {}
        for asset in config.assets:
            asset_by_id[asset.asset_id] = asset
            for src_id in asset.source_ids.values():
                asset_by_id.setdefault(src_id, asset)
        for obs in observations:
            mapped = _resolve_asset_mapping(obs, config) or asset_by_id.get(obs.asset_id)
            if mapped is not None:
                valid_labels = {
                    mapped.canonical_label.lower(),
                    mapped.asset_id.lower(),
                    *(a.lower() for a in mapped.aliases),
                    *(s.lower() for s in mapped.source_ids.values()),
                }
                if obs.observed_label.strip().lower() not in valid_labels:
                    contradictions.append(
                        ContradictionRecord(
                            summary=(
                                f"Source {obs.source!r} binds asset_id {obs.asset_id!r} "
                                f"(canonical {mapped.canonical_label!r}) to conflicting label "
                                f"{obs.observed_label!r}."
                            ),
                            claims=(
                                ContradictionClaim(
                                    source="facility_config",
                                    asset_id=mapped.asset_id,
                                    field="canonical_label",
                                    value=mapped.canonical_label,
                                    observed_at=obs.observed_at,
                                ),
                                ContradictionClaim(
                                    source=obs.source,
                                    asset_id=obs.asset_id,
                                    field="observed_label",
                                    value=obs.observed_label,
                                    observed_at=obs.observed_at,
                                ),
                            ),
                            unresolved=True,
                        )
                    )

        # 2. Intra-source and cross-source asset_id / area conflicts for the same observed_label
        by_label_and_source: dict[str, dict[str, list[Observation]]] = {}
        for obs in observations:
            norm_label = obs.observed_label.strip().lower()
            by_label_and_source.setdefault(norm_label, {}).setdefault(obs.source, []).append(obs)

        for label, per_source in by_label_and_source.items():
            source_names = sorted(per_source.keys())

            # 2a. Intra-source conflicts across multiple records from the same source
            for source_name in source_names:
                unique_in_source: dict[tuple[str, str | None], Observation] = {}
                for obs in per_source[source_name]:
                    canon_id = _canonical_asset_id(obs, config)
                    unique_in_source.setdefault((canon_id, obs.area), obs)
                if len(unique_in_source) >= 2:
                    reps = list(unique_in_source.values())
                    claims = tuple(
                        ContradictionClaim(
                            source=o.source,
                            asset_id=o.asset_id,
                            field="asset_id_area",
                            value=f"{o.asset_id}@{o.area or 'unknown'}",
                            observed_at=o.observed_at,
                        )
                        for o in reps
                    )
                    contradictions.append(
                        ContradictionRecord(
                            summary=(
                                f"Intra-source identity conflict in {source_name!r} "
                                f"for label {label!r}: "
                                + "; ".join(f"{o.asset_id}({o.area})" for o in reps)
                            ),
                            claims=claims,
                            unresolved=True,
                        )
                    )

            # 2b. Cross-source conflicts across ALL observations from distinct sources
            if len(per_source) < 2:
                continue
            unique_source_claims: dict[tuple[str, str, str | None], Observation] = {}
            for source_name in source_names:
                for obs in per_source[source_name]:
                    canon_id = _canonical_asset_id(obs, config)
                    unique_source_claims.setdefault((obs.source, canon_id, obs.area), obs)
            distinct_ids = {
                (_canonical_asset_id(o, config), o.area) for o in unique_source_claims.values()
            }
            if len(distinct_ids) >= 2:
                reps = list(unique_source_claims.values())
                claims = tuple(
                    ContradictionClaim(
                        source=o.source,
                        asset_id=o.asset_id,
                        field="asset_id_area",
                        value=f"{o.asset_id}@{o.area or 'unknown'}",
                        observed_at=o.observed_at,
                    )
                    for o in reps
                )
                contradictions.append(
                    ContradictionRecord(
                        summary=(
                            f"Cross-source identity conflict for label {label!r}: "
                            + "; ".join(
                                f"{o.source}->{o.asset_id}({o.area})" for o in reps
                            )
                        ),
                        claims=claims,
                        unresolved=True,
                    )
                )

        return tuple(contradictions)

    def verify_and_synthesize(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        observations: Sequence[Observation],
        source_errors: Mapping[str, str] | None = None,
        run_id: str = "run-verify",
        target_asset_query: str = "bomba 34",
        target_area: str | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        reference_time: datetime | None = None,
        metrics: ExecutionMetrics | None = None,
    ) -> Result:
        """Verify all collected observations and synthesize a deterministic Result contract."""
        ref_utc = ensure_utc(reference_time) if reference_time is not None else utc_now()
        eff_end = ensure_utc(window_end) if window_end is not None else ref_utc
        eff_start = (
            ensure_utc(window_start)
            if window_start is not None
            else eff_end - timedelta(seconds=config.time_window.lookback_seconds)
        )
        errors_dict = dict(source_errors or {})
        exec_metrics = metrics if metrics is not None else ExecutionMetrics()

        # Check auth expiry first (A10)
        auth_expired_sources = [
            src for src, err in errors_dict.items() if "auth_expired" in err.lower()
        ]
        if auth_expired_sources:
            verified_partial = tuple(
                self.verify_observation(
                    obs,
                    task.evidence_requirements,
                    config=config,
                    window_start=eff_start,
                    window_end=eff_end,
                    reference_time=ref_utc,
                )
                for obs in observations
            )
            return Result(
                task_id=task.task_id,
                run_id=run_id,
                status=TaskStatus.WAITING_FOR_INPUT,
                answer=(
                    "Authentication expired for source(s): "
                    f"{', '.join(auth_expired_sources)}. Waiting for human re-authentication."
                ),
                verified_observations=verified_partial,
                partial_info={
                    "source_errors": errors_dict,
                    "auth_expired_sources": auth_expired_sources,
                },
                required_action=(
                    "Re-authenticate expired session(s) for: "
                    + ", ".join(auth_expired_sources)
                ),
                execution_metrics=exec_metrics,
            )

        # Verify every observation deterministically
        verified_obs = tuple(
            self.verify_observation(
                obs,
                task.evidence_requirements,
                config=config,
                window_start=eff_start,
                window_end=eff_end,
                reference_time=ref_utc,
            )
            for obs in observations
        )

        # Check multi-area ambiguity (A02) before merging or guessing
        is_ambiguous, _, ambiguity_action = self.detect_ambiguity(
            verified_obs,
            config,
            target_asset_query=target_asset_query,
            target_area=target_area,
        )
        if is_ambiguous and ambiguity_action is not None:
            return Result(
                task_id=task.task_id,
                run_id=run_id,
                status=TaskStatus.WAITING_FOR_INPUT,
                answer=ambiguity_action,
                verified_observations=verified_obs,
                required_action=ambiguity_action,
                execution_metrics=exec_metrics,
            )

        # Detect contradictions (A13) without merging
        contradictions = self.detect_contradictions(verified_obs, config)

        authorized_obs = [obs for obs in verified_obs if obs.authorized_evidence]
        rejected_obs = [obs for obs in verified_obs if not obs.authorized_evidence]

        available_sources = sorted({obs.source for obs in authorized_obs})
        missing_sources = sorted(errors_dict.keys())

        if not authorized_obs and missing_sources:
            return Result(
                task_id=task.task_id,
                run_id=run_id,
                status=TaskStatus.FAILED,
                answer=(
                    "All requested industrial sources failed or returned no authorized evidence: "
                    + ", ".join(f"{k} ({v})" for k, v in sorted(errors_dict.items()))
                ),
                verified_observations=verified_obs,
                partial_info={
                    "available_sources": available_sources,
                    "missing_sources": missing_sources,
                    "source_errors": errors_dict,
                },
                contradictions=contradictions,
                execution_metrics=exec_metrics,
            )

        # Synthesize chronological facts strictly from authorized observations
        alarms = sorted(
            [
                o
                for o in authorized_obs
                if o.source == "scada"
                and o.metadata.get("record_type") == "alarm"
                and o.source_time is not None
            ],
            key=lambda o: o.source_time or ref_utc,
        )
        readings = sorted(
            [
                o
                for o in authorized_obs
                if o.source == "scada"
                and o.metadata.get("record_type") == "reading"
                and o.source_time is not None
            ],
            key=lambda o: o.source_time or ref_utc,
        )
        work_orders = sorted(
            [
                o
                for o in authorized_obs
                if o.source == "maintenance" and o.source_time is not None
            ],
            key=lambda o: o.source_time or ref_utc,
        )

        answer_parts: list[str] = []
        if alarms:
            first_alarm = alarms[0]
            alarm_ts = (
                first_alarm.source_time.isoformat() if first_alarm.source_time else "unknown"
            )
            answer_parts.append(
                f"First authorized alarm [{first_alarm.metadata.get('record_id')}]: "
                f"{first_alarm.value} at {alarm_ts} (asset={first_alarm.asset_id}, "
                f"area={first_alarm.area}, source=scada)."
            )
        if readings:
            latest_reading = readings[-1]
            rdg_ts = (
                latest_reading.source_time.isoformat() if latest_reading.source_time else "unknown"
            )
            answer_parts.append(
                f"Latest authorized reading [{latest_reading.metadata.get('record_id')}]: "
                f"{latest_reading.value} {latest_reading.unit or ''} at {rdg_ts} "
                f"(quality={latest_reading.quality.value}, source=scada)."
            )
        if work_orders:
            latest_wo = work_orders[-1]
            wo_ts = latest_wo.source_time.isoformat() if latest_wo.source_time else "unknown"
            answer_parts.append(
                f"Latest maintenance intervention [{latest_wo.metadata.get('order_id')}]: "
                f"{latest_wo.value} at {wo_ts} (asset={latest_wo.asset_id}, "
                f"area={latest_wo.area}, source=maintenance)."
            )
        if rejected_obs:
            rejected_desc = ", ".join(
                f"{o.metadata.get('record_id', o.asset_id)}({o.quality.value})"
                for o in rejected_obs
            )
            answer_parts.append(f"Excluded non-authorized/stale/bad records: {rejected_desc}.")
        if errors_dict:
            answer_parts.append(
                "Unavailable sources: "
                + ", ".join(f"{src}={msg}" for src, msg in sorted(errors_dict.items()))
                + "."
            )
        if contradictions:
            answer_parts.append(
                "Unresolved contradictions detected: "
                + "; ".join(c.summary for c in contradictions)
            )

        partial_info: dict[str, Any] | None = None
        if errors_dict or rejected_obs:
            partial_info = {
                "available_sources": available_sources,
                "missing_sources": missing_sources,
                "source_errors": errors_dict,
                "rejected_record_ids": [
                    o.metadata.get("record_id", o.asset_id) for o in rejected_obs
                ],
            }

        has_partial_source_failure = bool(errors_dict) and (
            task.evidence_requirements.allow_partial_on_source_failure
        )
        if errors_dict and not task.evidence_requirements.allow_partial_on_source_failure:
            final_status = TaskStatus.FAILED
        elif contradictions or has_partial_source_failure:
            final_status = TaskStatus.PARTIAL
        elif authorized_obs:
            final_status = TaskStatus.SUCCEEDED
        else:
            final_status = TaskStatus.FAILED

        return Result(
            task_id=task.task_id,
            run_id=run_id,
            status=final_status,
            answer=" ".join(answer_parts) if answer_parts else "No authorized evidence found.",
            verified_observations=verified_obs,
            partial_info=partial_info,
            contradictions=contradictions,
            execution_metrics=exec_metrics,
        )
