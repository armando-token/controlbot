"""2-Stage LaneRouter with deterministic lexical routing & low-confidence clarification (CB-10)."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Literal, Protocol

from pydantic import Field

from src.adapters.config import AssetMapping, FacilityConfig, resolve_asset_candidates
from src.contracts.common import FrozenModel, NonEmptyStr
from src.contracts.envelope import Lane, VerdictState

_TAG_RE = re.compile(
    r"\b(?:PT|TT|FT|LT|VFD|FIC|TIC|PIC|LIC|WO|CN|ALM|P)-[A-Z0-9_-]+\b",
    re.IGNORECASE,
)
_PLANT_UNIT_PHRASE_RE = re.compile(
    r"\b(?:pump|v[aá]lvula|valve|motor|compresor|compressor|sensor|transmisor|transmitter|tanque|tank)\s+([a-z0-9_-]+)\b",
    re.IGNORECASE,
)
_BARE_ASSET_NUMBER_RE = re.compile(
    r"\b(?:revisa|check|estado|status|lectura|alarmas?|alarms?)\s+(?:el|la|of|for)?\s*(\d{2,4}[a-z]?)\b",
    re.IGNORECASE,
)

_INDUSTRIAL_KEYWORDS: tuple[str, ...] = (
    "scada",
    "cmms",
    "erp",
    "plc",
    "historiador",
    "historian",
    "horner",
    "cscape",
    "pump",
    "valvula",
    "válvula",
    "valve",
    "alarma",
    "alarm",
    "lectura",
    "reading",
    "orden de trabajo",
    "work order",
    "mantenimiento",
    "maintenance",
    "presion",
    "presión",
    "temperatura",
    "temperature",
    "vibracion",
    "vibración",
    "caudal",
    "planta",
    "plant",
    "area-",
    "área",
)

_WEB_GENERAL_KEYWORDS: tuple[str, ...] = (
    "reemplazo",
    "replacement",
    "equivalente",
    "equivalent",
    "alternativa",
    "alternative",
    "datasheet",
    "web",
    "buscar",
    "search",
    "proveedor",
    "supplier",
    "precio",
    "price",
    "oem",
    "fabricante",
    "manufacturer",
    "manual",
    "especificaciones",
    "specs",
    "discontinued",
    "descontinuado",
)

_EXCEL_KEYWORDS: tuple[str, ...] = (
    "excel",
    "xlsx",
    "spreadsheet",
    "hoja de cálculo",
    "hoja de calculo",
    "workbook",
    "presupuesto",
    "cotización",
    "cotizacion",
    "tabla",
)

_GENERAL_GREETING_OR_TASK_RE = re.compile(
    r"^\s*(?:hi|hello|hey|hola|buenos\s+d[ií]as|buenas|thanks|gracias|help|ayuda|resume|summarize|write|draft|create|explain|translate|what\s+is|who\s+is|how\s+to)\b",
    re.IGNORECASE,
)


class AssetCandidate(FrozenModel):
    """Candidate facility asset presented during clarification."""

    asset_id: NonEmptyStr
    canonical_label: NonEmptyStr
    area: str | None = None
    score: float = Field(default=1.0, ge=0.0, le=1.0)


class RouteDecision(FrozenModel):
    """Output of LaneRouter.route() specifying lane, profile, verifiers, and clarification."""

    lane: Lane
    domain_profile: NonEmptyStr
    confidence: float = Field(ge=0.0, le=1.0)
    required_verifiers: tuple[NonEmptyStr, ...] = ()
    verdict_override: VerdictState | None = None
    needs_clarification: bool = False
    clarification_candidates: tuple[AssetCandidate, ...] = ()
    general_fallback_available: bool = True
    stage_used: Literal["explicit_ui", "stage1_lexical", "stage2_classifier", "fallback"]
    rationale: NonEmptyStr


class FastClassifier(Protocol):
    """Optional Stage-2 fast structured classifier (<300ms budget)."""

    async def classify(
        self,
        query: str,
        context: dict[str, Any],
    ) -> tuple[Lane, str, float, tuple[str, ...]]:
        """Return (lane, domain_profile, confidence, required_verifiers)."""
        ...


def _collect_asset_candidates(
    query: str,
    facility_config: FacilityConfig | None,
    area: str | None,
) -> list[AssetCandidate]:
    if facility_config is None:
        return []

    found: dict[tuple[str, str | None], AssetCandidate] = {}
    q_low = query.lower()

    def _add(asset: AssetMapping, score: float) -> None:
        key = (asset.asset_id, asset.area)
        if key not in found or score > found[key].score:
            found[key] = AssetCandidate(
                asset_id=asset.asset_id,
                canonical_label=asset.canonical_label,
                area=asset.area,
                score=score,
            )

    # Check exact tags/phrases extracted from query
    for tag_match in _TAG_RE.findall(query):
        for asset in resolve_asset_candidates(facility_config, tag_match, area=area):
            _add(asset, 1.0)

    for phrase_match in _PLANT_UNIT_PHRASE_RE.finditer(query):
        full_phrase = phrase_match.group(0)
        for asset in resolve_asset_candidates(facility_config, full_phrase, area=area):
            _add(asset, 1.0)

    for bare_match in _BARE_ASSET_NUMBER_RE.finditer(query):
        num = bare_match.group(1)
        for asset in facility_config.assets:
            if area is not None and asset.area != area:
                continue
            tokens = {
                asset.asset_id.lower(),
                asset.canonical_label.lower(),
                *(a.lower() for a in asset.aliases),
            }
            if any(re.search(rf"\b{re.escape(num.lower())}\b", tok) for tok in tokens):
                _add(asset, 0.75)

    # Check direct canonical label / alias / asset_id substring containment
    for asset in facility_config.assets:
        if area is not None and asset.area != area:
            continue
        names = [asset.asset_id, asset.canonical_label, *asset.aliases, *asset.source_ids.values()]
        for name in names:
            n_low = name.strip().lower()
            if len(n_low) >= 3 and re.search(
                rf"(?<![a-z0-9]){re.escape(n_low)}(?![a-z0-9])", q_low
            ):
                _add(asset, 0.95)
                break

    # Config-driven fallback for any facility asset noun + alphanumeric ID
    if not found:
        q_words = set(re.findall(r"[a-z0-9]{2,}", q_low))
        q_nums = set(re.findall(r"\b\d{2,4}[a-z]?\b", q_low))
        if q_nums:
            for asset in facility_config.assets:
                if area is not None and asset.area != area:
                    continue
                asset_text = " ".join(
                    [asset.asset_id, asset.canonical_label, *asset.aliases]
                ).lower()
                a_words = set(re.findall(r"[a-z]{4,}", asset_text))
                a_nums = set(re.findall(r"\b\d{2,4}[a-z]?\b", asset_text))
                if (q_words & a_words) and (q_nums & a_nums):
                    _add(asset, 0.85)

    return list(found.values())


def _extract_areas_from_query(
    query: str, facility_config: FacilityConfig | None
) -> list[str]:
    if facility_config is None:
        return []
    q_low = query.lower()
    matched: list[str] = []
    for area_id, area_cfg in facility_config.areas.items():
        if re.search(rf"(?<![a-z0-9]){re.escape(area_id.lower())}(?![a-z0-9])", q_low):
            matched.append(area_id)
            continue
        disp_low = area_cfg.display_name.lower()
        if len(disp_low) >= 3 and disp_low in q_low:
            matched.append(area_id)
    return matched


class LaneRouter:
    """Two-stage router: 0ms lexical/tag Stage 1 + bounded <300ms Stage 2 classifier."""

    def __init__(
        self,
        *,
        classifier: FastClassifier | None = None,
        confidence_threshold: float = 0.70,
        stage2_timeout_s: float = 0.30,
    ) -> None:
        self._classifier = classifier
        self._confidence_threshold = confidence_threshold
        self._stage2_timeout_s = stage2_timeout_s

    async def route(
        self,
        query: str,
        *,
        ui_lane: Lane | None = None,
        facility_config: FacilityConfig | None = None,
        area: str | None = None,
    ) -> RouteDecision:
        """Route query into general | industrial | mixed or pause with needs_clarification."""
        clean_query = query.strip()

        # Explicit UI GENERAL lane MUST short-circuit before plant disambiguation
        if ui_lane == Lane.GENERAL:
            return RouteDecision(
                lane=Lane.GENERAL,
                domain_profile="general_office",
                confidence=1.0,
                required_verifiers=(),
                stage_used="explicit_ui",
                rationale="Explicit UI lane selected: general.",
            )

        matched_areas = (
            [area] if area is not None else _extract_areas_from_query(clean_query, facility_config)
        )
        effective_area: str | None = matched_areas[0] if len(matched_areas) == 1 else None
        candidates = _collect_asset_candidates(clean_query, facility_config, effective_area)
        if len(matched_areas) >= 2:
            area_set = set(matched_areas)
            scoped_cands = [c for c in candidates if c.area in area_set]
            if scoped_cands:
                candidates = scoped_cands

        # Multi-area or multi-asset ambiguity check when unscoped to a single area
        if effective_area is None and (len(matched_areas) >= 2 or len(candidates) >= 2):
            distinct_ids = {c.asset_id for c in candidates}
            distinct_areas = {c.area for c in candidates if c.area is not None}
            if len(matched_areas) >= 2 or len(distinct_ids) >= 2 or len(distinct_areas) >= 2:
                return RouteDecision(
                    lane=ui_lane or Lane.INDUSTRIAL,
                    domain_profile="industrial_ot",
                    confidence=0.45,
                    required_verifiers=("industrial_reconciler",),
                    verdict_override=VerdictState.NEEDS_CLARIFICATION,
                    needs_clarification=True,
                    clarification_candidates=tuple(candidates),
                    general_fallback_available=True,
                    stage_used="stage1_lexical" if ui_lane is None else "explicit_ui",
                    rationale=(
                        f"Ambiguous multi-area/multi-asset query "
                        f"(areas={matched_areas or 'unspecified'}, candidates={len(candidates)}); "
                        "clarification required before querying OT sources."
                    ),
                )

        # Explicit UI lane override
        if ui_lane is not None:
            if ui_lane == Lane.INDUSTRIAL:
                verifiers: tuple[str, ...] = ("industrial_reconciler",)
                profile = "industrial_ot"
            elif ui_lane == Lane.MIXED:
                verifiers = ("industrial_reconciler", "airlock", "web_citation")
                profile = "mixed_industrial_web"
            else:
                verifiers = ()
                profile = "general_office"
            return RouteDecision(
                lane=ui_lane,
                domain_profile=profile,
                confidence=1.0,
                required_verifiers=verifiers,
                stage_used="explicit_ui",
                rationale=f"Explicit UI lane selected: {ui_lane.value}.",
            )

        q_low = clean_query.lower()
        has_tag = (
            _TAG_RE.search(clean_query) is not None
            or _PLANT_UNIT_PHRASE_RE.search(clean_query) is not None
        )
        has_ind_kw = any(kw in q_low for kw in _INDUSTRIAL_KEYWORDS)
        has_web_kw = any(kw in q_low for kw in _WEB_GENERAL_KEYWORDS)
        has_excel_kw = any(kw in q_low for kw in _EXCEL_KEYWORDS)
        has_ambiguous_bare_num = _BARE_ASSET_NUMBER_RE.search(clean_query) is not None

        has_industrial = has_tag or has_ind_kw or bool(candidates)
        has_external_general = has_web_kw or has_excel_kw

        # Stage 1: Mixed (Industrial + Web/Replacement/Excel)
        if has_industrial and has_external_general:
            mixed_verifiers: list[str] = ["industrial_reconciler", "airlock"]
            if has_web_kw:
                mixed_verifiers.append("web_citation")
            if has_excel_kw:
                mixed_verifiers.append("spreadsheet")
            return RouteDecision(
                lane=Lane.MIXED,
                domain_profile="mixed_industrial_web",
                confidence=0.92,
                required_verifiers=tuple(mixed_verifiers),
                stage_used="stage1_lexical",
                rationale="Detected both plant/industrial signals and external web/office intent.",
            )

        # Stage 1: Pure Industrial
        if has_industrial:
            return RouteDecision(
                lane=Lane.INDUSTRIAL,
                domain_profile="industrial_ot",
                confidence=0.92 if (has_tag or candidates) else 0.85,
                required_verifiers=("industrial_reconciler",),
                stage_used="stage1_lexical",
                rationale="Detected industrial tags, asset reference, or OT system keywords.",
            )

        # Stage 1: Pure Excel / Cited Web Research
        if has_excel_kw or has_web_kw:
            gen_verifiers: list[str] = []
            if has_web_kw:
                gen_verifiers.append("web_citation")
            if has_excel_kw:
                gen_verifiers.append("spreadsheet")
            profile = "office_excel" if has_excel_kw and not has_web_kw else "web_research"
            return RouteDecision(
                lane=Lane.GENERAL,
                domain_profile=profile,
                confidence=0.93,
                required_verifiers=tuple(gen_verifiers),
                stage_used="stage1_lexical",
                rationale="Detected deterministic office/Excel or cited web research intent.",
            )

        # Ambiguous bare numeric plant fragment (e.g. "revisa el 34") without clear context
        if has_ambiguous_bare_num and not candidates:
            return RouteDecision(
                lane=Lane.INDUSTRIAL,
                domain_profile="industrial_ot",
                confidence=0.40,
                required_verifiers=("industrial_reconciler",),
                verdict_override=VerdictState.NEEDS_CLARIFICATION,
                needs_clarification=True,
                general_fallback_available=True,
                stage_used="stage1_lexical",
                rationale="Ambiguous numeric reference without asset or area context.",
            )

        # Clear general conversational / writing prompt -> fast Stage 1 pass
        if (
            _GENERAL_GREETING_OR_TASK_RE.search(clean_query)
            or len(clean_query.split()) <= 3
            and not has_ambiguous_bare_num
        ) and self._classifier is None:
            return RouteDecision(
                lane=Lane.GENERAL,
                domain_profile="general_office",
                confidence=0.88,
                required_verifiers=(),
                stage_used="stage1_lexical",
                rationale="General conversational or office prompt without industrial signals.",
            )

        # Stage 2: Fast structured classifier (<300ms) when Stage 1 is inconclusive
        if self._classifier is not None:
            try:
                lane, profile, conf, verifiers_seq = await asyncio.wait_for(
                    self._classifier.classify(
                        clean_query,
                        {"area": effective_area, "has_facility": facility_config is not None},
                    ),
                    timeout=self._stage2_timeout_s,
                )
            except (TimeoutError, Exception) as exc:  # noqa: BLE001
                return RouteDecision(
                    lane=Lane.GENERAL,
                    domain_profile="general_office",
                    confidence=0.0,
                    required_verifiers=(),
                    verdict_override=VerdictState.NEEDS_CLARIFICATION,
                    needs_clarification=True,
                    general_fallback_available=True,
                    stage_used="stage2_classifier",
                    rationale=(
                        f"Stage-2 classifier unavailable or timed out ({exc}); "
                        "clarification requested."
                    ),
                )

            if conf < self._confidence_threshold:
                return RouteDecision(
                    lane=lane,
                    domain_profile=profile,
                    confidence=conf,
                    required_verifiers=tuple(verifiers_seq),
                    verdict_override=VerdictState.NEEDS_CLARIFICATION,
                    needs_clarification=True,
                    general_fallback_available=True,
                    stage_used="stage2_classifier",
                    rationale=(
                        f"Classifier confidence {conf:.2f} < threshold "
                        f"{self._confidence_threshold:.2f}; clarification required."
                    ),
                )

            return RouteDecision(
                lane=lane,
                domain_profile=profile,
                confidence=conf,
                required_verifiers=tuple(verifiers_seq),
                stage_used="stage2_classifier",
                rationale=f"Classified by Stage-2 model with confidence {conf:.2f}.",
            )

        return RouteDecision(
            lane=Lane.GENERAL,
            domain_profile="general_office",
            confidence=0.82,
            required_verifiers=(),
            stage_used="fallback",
            rationale=(
                "Defaulted to general lane in absence of industrial signals or Stage-2 classifier."
            ),
        )


__all__ = [
    "AssetCandidate",
    "FastClassifier",
    "LaneRouter",
    "RouteDecision",
]
