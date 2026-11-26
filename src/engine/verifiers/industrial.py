"""Industrial verifiers: units, AssetResolver, HealthGuard, FreshnessPolicy, Reconciler."""

from __future__ import annotations

import difflib
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from src.adapters.config import AssetMapping, FacilityConfig, resolve_asset_candidates
from src.adapters.verifier import Verifier, _canonical_asset_id, _resolve_asset_mapping_any_source
from src.contracts.common import FrozenModel, NonEmptyStr, ensure_utc, utc_now
from src.contracts.envelope import Lane, VerdictState, VerifiedResponseMeta
from src.contracts.models import (
    ContradictionClaim,
    ContradictionRecord,
    Observation,
    Result,
    TaskSpec,
)

_UNIT_ALIASES: dict[str, str] = {
    "psi": "psi",
    "psia": "psi",
    "psig": "psi",
    "bar": "bar",
    "bara": "bar",
    "barg": "bar",
    "kpa": "kpa",
    "c": "C",
    "°c": "C",
    "degc": "C",
    "celsius": "C",
    "f": "F",
    "°f": "F",
    "degf": "F",
    "fahrenheit": "F",
}

_PRESSURE_TO_BAR: dict[str, float] = {
    "bar": 1.0,
    "psi": 0.0689475729,
    "kpa": 0.01,
}


def canonical_unit_name(unit: str) -> str:
    """Normalize unit spelling/degree sign (e.g. '°C' -> 'C', '°F' -> 'F', 'PSI' -> 'psi')."""
    cleaned = unit.strip().lower()
    return _UNIT_ALIASES.get(cleaned, unit.strip())


def unit_dimension(unit: str) -> str | None:
    canon = canonical_unit_name(unit)
    if canon in _PRESSURE_TO_BAR:
        return "pressure"
    if canon in {"C", "F"}:
        return "temperature"
    return None


def normalize_unit_and_value(value: float, unit: str, target_unit: str) -> tuple[float, str]:
    """Convert numeric value between compatible industrial units (psi<->bar<->kPa, F<->C)."""
    src = canonical_unit_name(unit)
    dst = canonical_unit_name(target_unit)
    if src == dst:
        return float(value), dst

    if src in _PRESSURE_TO_BAR and dst in _PRESSURE_TO_BAR:
        in_bar = float(value) * _PRESSURE_TO_BAR[src]
        converted = in_bar / _PRESSURE_TO_BAR[dst]
        return converted, dst

    if src == "F" and dst == "C":
        return (float(value) - 32.0) * 5.0 / 9.0, "C"
    if src == "C" and dst == "F":
        return float(value) * 9.0 / 5.0 + 32.0, "F"

    raise ValueError(f"Incompatible industrial units: cannot convert {unit!r} to {target_unit!r}.")


def format_duration_human(seconds: float) -> str:
    """Format elapsed seconds into concise human-readable duration (e.g. '19 h', '15 min')."""
    secs = max(0.0, seconds)
    if secs >= 3600.0:
        hours = secs / 3600.0
        if abs(hours - round(hours)) < 0.05:
            return f"{int(round(hours))} h"
        return f"{hours:.1f} h"
    if secs >= 60.0:
        mins = secs / 60.0
        if abs(mins - round(mins)) < 0.05:
            return f"{int(round(mins))} min"
        return f"{mins:.1f} min"
    return f"{int(round(secs))} s"


class AssetCandidateMatch(FrozenModel):
    """Ranked nearest asset candidate returned when exact asset resolution fails."""

    asset_id: NonEmptyStr
    canonical_label: NonEmptyStr
    area: str | None = None
    location_display: str
    score: float = Field(ge=0.0, le=1.0)


class AssetResolution(FrozenModel):
    """Outcome of AssetResolver.resolve() — never silently substitutes unknown tags."""

    status: Literal["found", "ambiguous", "not_found"]
    verdict: VerdictState
    query: NonEmptyStr
    resolved: AssetMapping | None = None
    candidates: tuple[AssetMapping, ...] = ()
    nearest_assets: tuple[AssetCandidateMatch, ...] = ()
    alias_suggestion_prompt: str | None = None


class AssetResolver:
    """Resolves asset tags/labels or returns top-3 nearest candidates on asset_not_found."""

    @staticmethod
    def _token_set(text: str) -> set[str]:
        return set(re.findall(r"[a-z0-9]+", text.lower()))

    @classmethod
    def _score_asset(cls, query: str, asset: AssetMapping) -> float:
        q_norm = re.sub(r"[^a-z0-9]+", "", query.lower())
        q_tokens = cls._token_set(query)
        candidates = [
            asset.asset_id,
            asset.canonical_label,
            *asset.aliases,
            *asset.source_ids.values(),
        ]
        best = 0.0
        for cand in candidates:
            c_norm = re.sub(r"[^a-z0-9]+", "", cand.lower())
            if not c_norm:
                continue
            seq_ratio = difflib.SequenceMatcher(None, q_norm, c_norm).ratio()
            c_tokens = cls._token_set(cand)
            overlap = (
                (len(q_tokens & c_tokens) / max(1, len(q_tokens | c_tokens))) if q_tokens else 0.0
            )
            prefix_bonus = (
                0.15
                if (q_norm and (c_norm.startswith(q_norm[:3]) or q_norm.startswith(c_norm[:3])))
                else 0.0
            )
            score = min(1.0, max(seq_ratio, 0.55 * seq_ratio + 0.45 * overlap) + prefix_bonus)
            if score > best:
                best = score
        return round(best, 4)

    def resolve(
        self,
        config: FacilityConfig,
        query: str,
        *,
        area: str | None = None,
    ) -> AssetResolution:
        clean_q = query.strip()
        matches = resolve_asset_candidates(config, clean_q, area=area)
        if len(matches) == 1:
            return AssetResolution(
                status="found",
                verdict=VerdictState.VERIFIED,
                query=clean_q,
                resolved=matches[0],
            )
        if len(matches) >= 2:
            return AssetResolution(
                status="ambiguous",
                verdict=VerdictState.NEEDS_CLARIFICATION,
                query=clean_q,
                candidates=tuple(matches),
                alias_suggestion_prompt=(
                    f"El tag/equipo {clean_q!r} coincide con múltiples activos; "
                    "especifica el área o ID exacto."
                ),
            )

        ranked: list[AssetCandidateMatch] = []
        for asset in config.assets:
            area_cfg = config.areas.get(asset.area)
            loc_display = area_cfg.display_name if area_cfg is not None else asset.area
            ranked.append(
                AssetCandidateMatch(
                    asset_id=asset.asset_id,
                    canonical_label=asset.canonical_label,
                    area=asset.area,
                    location_display=loc_display,
                    score=self._score_asset(clean_q, asset),
                )
            )
        ranked.sort(key=lambda item: (-item.score, item.asset_id))
        top3 = tuple(ranked[:3])
        if top3:
            opts = ", ".join(
                f"{c.asset_id} ({c.canonical_label} — {c.location_display})" for c in top3
            )
            prompt = (
                f"No se encontró el activo {clean_q!r} en la configuración de planta. "
                f"Activos más cercanos: {opts}. ¿Deseas registrar un alias o seleccionar uno?"
            )
        else:
            prompt = f"No se encontró el activo {clean_q!r} y no hay activos configurados."

        return AssetResolution(
            status="not_found",
            verdict=VerdictState.ASSET_NOT_FOUND,
            query=clean_q,
            nearest_assets=top3,
            alias_suggestion_prompt=prompt,
        )


class HealthStatus(FrozenModel):
    """Degraded-source health report produced by HealthGuard."""

    degraded: bool
    verdict: VerdictState
    unavailable_sources: tuple[str, ...] = ()
    available_sources: tuple[str, ...] = ()
    down_since: dict[str, str] = Field(default_factory=dict)
    degraded_banner: str | None = None
    abstained_fields: tuple[str, ...] = ()


class HealthGuard:
    """Detects HTTP 503 / SourceUnavailableError failures and emits degraded HH:MM banners."""

    @staticmethod
    def _is_unavailable_error(err_msg: str) -> bool:
        low = err_msg.lower()
        return any(
            tok in low
            for tok in (
                "503",
                "502",
                "504",
                "unavailable",
                "timeout",
                "timed out",
                "connection",
                "unreachable",
                "down",
            )
        )

    def evaluate_sources(
        self,
        source_errors: Mapping[str, str],
        *,
        down_since_by_source: Mapping[str, datetime] | None = None,
        available_sources: Sequence[str] = (),
        reference_time: datetime | None = None,
    ) -> HealthStatus:
        ref_utc = ensure_utc(reference_time) if reference_time is not None else utc_now()
        down_map = down_since_by_source or {}
        unavail: list[str] = []
        down_hhmm: dict[str, str] = {}
        abstained: list[str] = []

        for src, err in sorted(source_errors.items()):
            if self._is_unavailable_error(err) or src in source_errors:
                unavail.append(src)
                down_dt = ensure_utc(down_map[src]) if src in down_map else ref_utc
                down_hhmm[src] = down_dt.strftime("%H:%M")
                if "maint" in src.lower() or "cmms" in src.lower():
                    abstained.extend(["work_orders", "maintenance_status"])
                elif "scada" in src.lower():
                    abstained.extend(["live_readings", "alarms"])
                else:
                    abstained.append(f"{src}_data")

        avail_tuple = tuple(sorted(set(available_sources)))
        if not unavail:
            return HealthStatus(
                degraded=False,
                verdict=VerdictState.VERIFIED,
                available_sources=avail_tuple,
            )

        down_desc = ", ".join(
            f"{src.upper()} inaccesible desde {down_hhmm[src]}" for src in unavail
        )
        if avail_tuple:
            avail_desc = ", ".join(s.upper() for s in avail_tuple)
            banner = f"{down_desc}; análisis parcial solo con {avail_desc}"
            verdict = VerdictState.PARTIAL_EVIDENCE
        else:
            banner = f"{down_desc}; sin fuentes operativas disponibles"
            verdict = VerdictState.PARTIAL_EVIDENCE

        return HealthStatus(
            degraded=True,
            verdict=verdict,
            unavailable_sources=tuple(unavail),
            available_sources=avail_tuple,
            down_since=down_hhmm,
            degraded_banner=banner,
            abstained_fields=tuple(dict.fromkeys(abstained)),
        )


class FreshnessResult(FrozenModel):
    """Freshness TTL evaluation preventing stale data from passing as live telemetry."""

    is_stale: bool
    verdict: VerdictState
    age_seconds: float | None = Field(default=None, ge=0.0)
    max_ttl_seconds: float = Field(gt=0.0)
    age_display: str
    ttl_display: str
    message: str
    allow_as_current_reading: bool
    refresh_action: str | None = None


class FreshnessPolicy:
    """Enforces TTL freshness thresholds with exact age vs TTL formatting."""

    def check_freshness(
        self,
        obs: Observation,
        *,
        max_ttl_seconds: float,
        reference_time: datetime | None = None,
    ) -> FreshnessResult:
        ref_utc = ensure_utc(reference_time) if reference_time is not None else utc_now()
        ttl_disp = format_duration_human(max_ttl_seconds)

        if obs.source_time is None:
            return FreshnessResult(
                is_stale=True,
                verdict=VerdictState.STALE_DATA,
                age_seconds=None,
                max_ttl_seconds=max_ttl_seconds,
                age_display="desconocida",
                ttl_display=ttl_disp,
                message=f"Lectura sin timestamp de origen; límite de vigencia: {ttl_disp}",
                allow_as_current_reading=False,
                refresh_action="refresh_live_source",
            )

        age_s = max(0.0, (ref_utc - ensure_utc(obs.source_time)).total_seconds())
        age_disp = format_duration_human(age_s)
        is_stale = age_s > max_ttl_seconds
        if is_stale:
            return FreshnessResult(
                is_stale=True,
                verdict=VerdictState.STALE_DATA,
                age_seconds=age_s,
                max_ttl_seconds=max_ttl_seconds,
                age_display=age_disp,
                ttl_display=ttl_disp,
                message=f"Última lectura hace {age_disp}; límite de vigencia: {ttl_disp}",
                allow_as_current_reading=False,
                refresh_action="refresh_live_source",
            )

        return FreshnessResult(
            is_stale=False,
            verdict=VerdictState.VERIFIED,
            age_seconds=age_s,
            max_ttl_seconds=max_ttl_seconds,
            age_display=age_disp,
            ttl_display=ttl_disp,
            message=f"Lectura vigente (hace {age_disp}; límite: {ttl_disp})",
            allow_as_current_reading=True,
            refresh_action=None,
        )


class IndustrialReconcileResult(FrozenModel):
    """Unified reconciliation result with Agreements, Contradictions, Partial Evidence & Meta."""

    verdict: VerdictState
    agreements: tuple[str, ...] = ()
    contradictions: tuple[ContradictionRecord, ...] = ()
    partial_evidence: tuple[str, ...] = ()
    source_timestamps: dict[str, str] = Field(default_factory=dict)
    degraded_banner: str | None = None
    stale_info: dict[str, Any] | None = None
    nearest_assets: tuple[AssetCandidateMatch, ...] = ()
    meta: VerifiedResponseMeta
    legacy_result: Result | None = None


class IndustrialReconciler:
    """Wraps Verifier with unit conversion, HealthGuard, FreshnessPolicy & AssetResolver."""

    def __init__(
        self, *, numeric_rel_tolerance: float = 0.02, numeric_abs_tolerance: float = 0.5
    ) -> None:
        self._base_verifier = Verifier()
        self._asset_resolver = AssetResolver()
        self._health_guard = HealthGuard()
        self._freshness_policy = FreshnessPolicy()
        self._rel_tol = numeric_rel_tolerance
        self._abs_tol = numeric_abs_tolerance

    def _compare_numeric_readings(
        self,
        observations: Sequence[Observation],
        config: FacilityConfig,
    ) -> tuple[list[str], list[ContradictionRecord]]:
        agreements: list[str] = []
        contradictions: list[ContradictionRecord] = []

        # Group numeric observations by (canonical_asset_id, unit_dimension)
        grouped: dict[tuple[str, str], list[Observation]] = {}
        for obs in observations:
            if not isinstance(obs.value, (int, float)) or isinstance(obs.value, bool):
                continue
            if not obs.unit:
                continue
            dim = unit_dimension(obs.unit)
            if dim is None:
                continue
            canon_id = _canonical_asset_id(obs, config)
            grouped.setdefault((canon_id, dim), []).append(obs)

        for (canon_id, dim), obs_list in sorted(grouped.items()):
            distinct_sources = {o.source for o in obs_list}
            if len(distinct_sources) < 2:
                continue
            target_unit = "bar" if dim == "pressure" else "C"
            converted: list[tuple[Observation, float, str]] = []
            for o in obs_list:
                assert o.unit is not None
                c_val, c_unit = normalize_unit_and_value(float(o.value), o.unit, target_unit)  # type: ignore[arg-type]
                converted.append((o, c_val, c_unit))

            vals = [item[1] for item in converted]
            min_v, max_v = min(vals), max(vals)
            tol = max(self._abs_tol, abs(max_v) * self._rel_tol)
            if (max_v - min_v) <= tol:
                src_desc = ", ".join(
                    f"{o.source}={o.value} {o.unit} ({cv:.2f} {cu})" for o, cv, cu in converted
                )
                agreements.append(f"Acuerdo numérico ({dim}) para {canon_id}: {src_desc}.")
            else:
                claims = tuple(
                    ContradictionClaim(
                        source=o.source,
                        asset_id=o.asset_id,
                        field=f"{dim}_{cu}",
                        value=f"{o.value} {o.unit} (~{cv:.2f} {cu})",
                        observed_at=o.observed_at,
                    )
                    for o, cv, cu in converted
                )
                contradictions.append(
                    ContradictionRecord(
                        summary=(
                            f"Cross-source numeric {dim} contradiction for {canon_id}: "
                            + "; ".join(
                                f"{o.source}={o.value} {o.unit} (~{cv:.2f} {cu})"
                                for o, cv, cu in converted
                            )
                        ),
                        claims=claims,
                        unresolved=True,
                    )
                )

        return agreements, contradictions

    def reconcile(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        observations: Sequence[Observation],
        source_errors: Mapping[str, str] | None = None,
        down_since_by_source: Mapping[str, datetime] | None = None,
        target_asset_query: str = "",
        target_area: str | None = None,
        reference_time: datetime | None = None,
        max_ttl_seconds: float | None = None,
        run_id: str = "run-reconcile",
    ) -> IndustrialReconcileResult:
        ref_utc = ensure_utc(reference_time) if reference_time is not None else utc_now()
        errors_dict = dict(source_errors or {})

        # 1. Asset resolution check when explicit query is supplied
        nearest_assets: tuple[AssetCandidateMatch, ...] = ()
        if target_asset_query.strip():
            resolution = self._asset_resolver.resolve(config, target_asset_query, area=target_area)
            if resolution.status == "not_found":
                nearest_dicts = tuple(
                    {
                        "asset_id": c.asset_id,
                        "canonical_label": c.canonical_label,
                        "area": c.area or "",
                        "location_display": c.location_display,
                        "score": f"{c.score:.2f}",
                    }
                    for c in resolution.nearest_assets
                )
                meta = VerifiedResponseMeta(
                    verdict=VerdictState.ASSET_NOT_FOUND,
                    lane=Lane.INDUSTRIAL,
                    domain_profile="industrial_ot",
                    nearest_assets=nearest_dicts,
                    degraded_banner=resolution.alias_suggestion_prompt,
                )
                return IndustrialReconcileResult(
                    verdict=VerdictState.ASSET_NOT_FOUND,
                    partial_evidence=(resolution.alias_suggestion_prompt or "",),
                    nearest_assets=resolution.nearest_assets,
                    degraded_banner=resolution.alias_suggestion_prompt,
                    meta=meta,
                )
            if resolution.status == "ambiguous":
                cand_dicts = tuple(
                    {
                        "asset_id": c.asset_id,
                        "canonical_label": c.canonical_label,
                        "area": c.area,
                    }
                    for c in resolution.candidates
                )
                meta = VerifiedResponseMeta(
                    verdict=VerdictState.NEEDS_CLARIFICATION,
                    lane=Lane.INDUSTRIAL,
                    domain_profile="industrial_ot",
                    clarification_candidates=cand_dicts,
                )
                return IndustrialReconcileResult(
                    verdict=VerdictState.NEEDS_CLARIFICATION,
                    partial_evidence=(resolution.alias_suggestion_prompt or "",),
                    meta=meta,
                )

        # 2. Verify observations with unit-equivalence awareness (when dimension matches unit)
        adjusted_obs: list[Observation] = []
        for obs in observations:
            mapped = _resolve_asset_mapping_any_source(obs, config)
            obs_to_verify = obs
            if mapped is not None and obs.unit:
                rec_type = str(obs.metadata.get("record_type", ""))
                allowed_tuple = mapped.allowed_units.get(rec_type, ())
                if not allowed_tuple:
                    flat = [u for grp in mapped.allowed_units.values() for u in grp]
                    allowed_tuple = tuple(flat)
                if (
                    allowed_tuple
                    and obs.unit not in allowed_tuple
                    and isinstance(obs.value, (int, float))
                ):
                    for target_u in allowed_tuple:
                        try:
                            conv_v, conv_u = normalize_unit_and_value(
                                float(obs.value), obs.unit, target_u
                            )
                            obs_meta = dict(obs.metadata)
                            obs_meta["original_value"] = obs.value
                            obs_meta["original_unit"] = obs.unit
                            obs_to_verify = obs.model_copy(
                                update={"value": conv_v, "unit": conv_u, "metadata": obs_meta}
                            )
                            break
                        except ValueError:
                            continue
            verified_single = self._base_verifier.verify_observation(
                obs_to_verify,
                task.evidence_requirements,
                config=config,
                reference_time=ref_utc,
            )
            adjusted_obs.append(verified_single)

        # 3. FreshnessPolicy check
        ttl_s = (
            max_ttl_seconds
            or task.evidence_requirements.max_staleness_seconds
            or config.time_window.max_staleness_seconds
        )
        stale_results: list[tuple[Observation, FreshnessResult]] = []
        for obs in observations:
            if obs.metadata.get("record_type") == "reading" or obs.source_time is not None:
                fr = self._freshness_policy.check_freshness(
                    obs, max_ttl_seconds=ttl_s, reference_time=ref_utc
                )
                if fr.is_stale:
                    stale_results.append((obs, fr))

        # 4. Run base Verifier synthesis + numeric cross-source comparison
        legacy_result = self._base_verifier.verify_and_synthesize(
            task=task,
            config=config,
            observations=adjusted_obs,
            source_errors=errors_dict,
            run_id=run_id,
            target_asset_query=target_asset_query or "asset",
            target_area=target_area,
            reference_time=ref_utc,
        )

        num_agreements, num_contradictions = self._compare_numeric_readings(observations, config)
        all_contradictions = tuple(list(legacy_result.contradictions) + num_contradictions)

        authorized = [o for o in adjusted_obs if o.authorized_evidence]
        available_sources = sorted({o.source for o in authorized})
        health = self._health_guard.evaluate_sources(
            errors_dict,
            down_since_by_source=down_since_by_source,
            available_sources=available_sources,
            reference_time=ref_utc,
        )

        source_timestamps: dict[str, str] = {}
        for obs in observations:
            if obs.source_time is not None:
                source_timestamps[obs.source] = ensure_utc(obs.source_time).isoformat()

        agreements = list(num_agreements)
        if authorized and not all_contradictions:
            agreements.append(
                f"Fuentes autorizadas ({', '.join(available_sources)}) consistentes en "
                "identidad y ventana temporal."
            )

        partial_evidence: list[str] = []
        if health.degraded_banner:
            partial_evidence.append(health.degraded_banner)
        for o in adjusted_obs:
            if not o.authorized_evidence:
                reasons = ", ".join(o.metadata.get("rejection_reasons", []))
                partial_evidence.append(f"Excluida lectura de {o.source} ({o.asset_id}): {reasons}")

        stale_info: dict[str, Any] | None = None
        if stale_results:
            worst_obs, worst_fr = stale_results[0]
            stale_info = {
                "source": worst_obs.source,
                "asset_id": worst_obs.asset_id,
                "age_seconds": worst_fr.age_seconds,
                "max_ttl_seconds": worst_fr.max_ttl_seconds,
                "age_display": worst_fr.age_display,
                "ttl_display": worst_fr.ttl_display,
                "message": worst_fr.message,
                "refresh_action": worst_fr.refresh_action,
            }

        # Priority: contradictions > stale_data (no fresh obs) > partial_evidence > verified
        if all_contradictions:
            verdict = VerdictState.CONTRADICTED
        elif stale_results and not authorized:
            verdict = VerdictState.STALE_DATA
        elif health.degraded or partial_evidence:
            verdict = VerdictState.PARTIAL_EVIDENCE
        elif authorized:
            verdict = VerdictState.VERIFIED
        else:
            verdict = VerdictState.NOT_DOCUMENTED

        meta = VerifiedResponseMeta(
            verdict=verdict,
            lane=Lane.INDUSTRIAL,
            domain_profile="industrial_ot",
            agreements=tuple(agreements),
            contradictions=all_contradictions,
            partial_evidence=tuple(partial_evidence),
            stale_info=stale_info,
            degraded_banner=health.degraded_banner,
            citations=tuple(f"{src}@{ts}" for src, ts in sorted(source_timestamps.items())),
        )

        return IndustrialReconcileResult(
            verdict=verdict,
            agreements=tuple(agreements),
            contradictions=all_contradictions,
            partial_evidence=tuple(partial_evidence),
            source_timestamps=source_timestamps,
            degraded_banner=health.degraded_banner,
            stale_info=stale_info,
            nearest_assets=nearest_assets,
            meta=meta,
            legacy_result=legacy_result,
        )


__all__ = [
    "AssetCandidateMatch",
    "AssetResolution",
    "AssetResolver",
    "FreshnessPolicy",
    "FreshnessResult",
    "HealthGuard",
    "HealthStatus",
    "IndustrialReconcileResult",
    "IndustrialReconciler",
    "canonical_unit_name",
    "format_duration_human",
    "normalize_unit_and_value",
    "unit_dimension",
]
