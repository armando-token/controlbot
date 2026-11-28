"""Grok Bot (`main`/`test` ONLY) differential behavior cards & REF_UNAVAILABLE handling."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from src.contracts.common import utc_now
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.factory.errors import IsolationBoundaryError
from src.qa.isolation import (
    ALLOWED_GROKBOT_BOTS,
    _redact_encoded_auth,
    _sanitize_record,
    assert_allowed_grokbot_target,
    assert_safe_mutation_path,
    contains_encoded_auth,
    contains_unredacted_url_secret,
)
from src.qa.models import ReferenceBehaviorCard
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
    redact_string_strict,
)

FIVE_DIMENSIONS: tuple[str, ...] = (
    "discoverability",
    "state_transition",
    "independent_verification",
    "missing_data_or_permission",
    "efficiency_notes",
)

_M3_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![A-Za-z0-9])sk-(?:proj|live|test|ant|svcacct)?-?[A-Za-z0-9_-]{12,}"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{20,}"),
)

HARDWARE_ENV_DISCLAIMER: dict[str, Any] = {
    "environment_type": "xai_grok_bot_desktop_client_on_linux_vnc",
    "host_os": "Ubuntu 24.04.5 LTS",
    "kernel": "6.1.141 x86_64",
    "cpu": "16x Intel(R) Xeon(R) Processor @ 3.20GHz",
    "ram_gb": 62,
    "display": "DISPLAY=:1 Xtigervnc 1592x689",
    "window_size": "1040x662",
    "timing_comparability": "observational_only_different_hardware_and_cloud_backend",
    "privacy_scope": "main_and_test_only_no_tokens_cookies_or_asar_reverse_engineering",
    "truth_source_rule": "synthetic_fixtures_override_external_reference",
}

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_DEFAULT_CARDS_DIR: Path = _REPO_ROOT / "var" / "qa_campaigns" / "reference_cards"


def _validate_card_id(card_id: str) -> str:
    if (
        not card_id
        or card_id != card_id.strip()
        or "/" in card_id
        or "\\" in card_id
        or ".." in card_id
        or "\x00" in card_id
        or card_id in {".", ".."}
    ):
        raise ValueError(
            f"Invalid card_id {card_id!r}: path traversal or whitespace-padded IDs are forbidden."
        )
    return card_id


def _redact_string_m3(value: str) -> str:
    sanitized = _sanitize_record(value)
    scrubbed = redact_string_strict(
        _redact_encoded_auth(sanitized if isinstance(sanitized, str) else str(sanitized))
    )
    for pattern in _M3_TOKEN_PATTERNS:
        scrubbed = pattern.sub(REDACTED_PLACEHOLDER, scrubbed)
    return _redact_encoded_auth(scrubbed)


def _redact_payload_m3(value: Any) -> Any:
    strict_redacted = redact_payload_strict(_sanitize_record(value))

    def _walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            return {_walk(k): _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, tuple):
            return tuple(_walk(item) for item in node)
        if isinstance(node, set):
            return {_walk(item) for item in node}
        if isinstance(node, frozenset):
            return frozenset(_walk(item) for item in node)
        if isinstance(node, str):
            return _redact_string_m3(node)
        return node

    return _walk(strict_redacted)


def _contains_unredacted_secret_m3(value: Any) -> bool:
    if contains_unredacted_secret_strict(value):
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_unredacted_secret_m3(k) or _contains_unredacted_secret_m3(v)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_unredacted_secret_m3(item) for item in value)
    if isinstance(value, str):
        return (
            any(pattern.search(value) for pattern in _M3_TOKEN_PATTERNS)
            or contains_encoded_auth(value)
            or contains_unredacted_url_secret(value)
        )
    if value is not None:
        raw = str(value)
        return (
            any(pattern.search(raw) for pattern in _M3_TOKEN_PATTERNS)
            or contains_encoded_auth(raw)
            or contains_unredacted_url_secret(raw)
        )
    return False


def _prepare_conditions(conditions: Mapping[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = dict(HARDWARE_ENV_DISCLAIMER)
    if conditions:
        for key, value in conditions.items():
            merged[str(key)] = value
    redacted = _redact_payload_m3(merged)
    if not isinstance(redacted, dict):
        raise ValueError("Conditions payload must serialize to a mapping.")
    return redacted


def _require_allowed_bot(bot_name: str) -> Literal["main", "test"]:
    if bot_name != bot_name.strip():
        raise IsolationBoundaryError(
            f"Grok Bot target {bot_name!r} is forbidden; "
            "whitespace-padded bot names are not allowed (blocked)."
        )
    normalized = assert_allowed_grokbot_target(bot_name)
    return cast(Literal["main", "test"], normalized)


def build_ref_unavailable_card(
    *,
    case_id: str,
    reason: str,
    card_id: str | None = None,
    bot_used: str | None = None,
    app_version: str | None = "1.3.0",
    expected_controlbot_contract: str | None = None,
    conditions: Mapping[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> ReferenceBehaviorCard:
    """Build a valid `REF_UNAVAILABLE` card so local deterministic evaluation is never blocked."""
    typed_bot: Literal["main", "test"] | None = None
    if bot_used is not None:
        typed_bot = _require_allowed_bot(bot_used)

    clean_reason = _redact_string_m3(reason.strip())
    if not clean_reason:
        clean_reason = "Grok Bot reference session unavailable"

    clean_contract = _redact_string_m3(
        (
            expected_controlbot_contract
            or "Continue deterministic local evaluation on synthetic fixtures; "
            "record REF_UNAVAILABLE without blocking campaign."
        ).strip()
    )
    resolved_id = (
        card_id.strip()
        if card_id and card_id.strip()
        else f"ref-{case_id.strip().lower()}-unavailable"
    )
    safe_conditions = _prepare_conditions(conditions)
    card = ReferenceBehaviorCard(
        card_id=resolved_id,
        case_id=case_id.strip(),
        source="ref_unavailable",
        status="REF_UNAVAILABLE",
        unavailable_reason=clean_reason,
        bot_used=typed_bot,
        app_version=app_version,
        observed_at=observed_at or utc_now(),
        conditions=safe_conditions,
        discoverability="",
        state_transition="",
        independent_verification="",
        missing_data_or_permission="",
        efficiency_notes="",
        expected_controlbot_contract=clean_contract,
    )
    violations = validate_reference_card(card)
    if violations:
        raise ValueError(f"Invalid REF_UNAVAILABLE card {card.card_id!r}: {violations}")
    return card


def build_reference_card(
    *,
    card_id: str,
    case_id: str,
    source: Literal["grok_bot_app", "grok_bot_docs", "ref_unavailable"],
    status: Literal["observed", "documented", "REF_UNAVAILABLE"],
    bot_used: str | None = None,
    app_version: str | None = "1.3.0",
    unavailable_reason: str | None = None,
    conditions: Mapping[str, Any] | None = None,
    discoverability: str = "",
    state_transition: str = "",
    independent_verification: str = "",
    missing_data_or_permission: str = "",
    efficiency_notes: str = "",
    expected_controlbot_contract: str = "",
    observed_at: datetime | None = None,
) -> ReferenceBehaviorCard:
    """Construct, sanitize, and validate a differential behavior card."""
    typed_bot: Literal["main", "test"] | None = None
    if bot_used is not None:
        typed_bot = _require_allowed_bot(bot_used)

    if status == "REF_UNAVAILABLE":
        return build_ref_unavailable_card(
            case_id=case_id,
            reason=unavailable_reason or "Grok Bot reference unavailable",
            card_id=card_id,
            bot_used=typed_bot,
            app_version=app_version,
            expected_controlbot_contract=expected_controlbot_contract or None,
            conditions=conditions,
            observed_at=observed_at,
        )

    if source not in {"grok_bot_app", "grok_bot_docs"}:
        raise ValueError(
            f"Observed/documented card must use source 'grok_bot_app' or 'grok_bot_docs', "
            f"got {source!r}."
        )
    if source == "grok_bot_app" and typed_bot not in ALLOWED_GROKBOT_BOTS:
        raise ValueError(
            "Cards with source='grok_bot_app' require bot_used in {'main', 'test'}."
        )

    dimensions: dict[str, str] = {
        "discoverability": _redact_string_m3(discoverability.strip()),
        "state_transition": _redact_string_m3(state_transition.strip()),
        "independent_verification": _redact_string_m3(independent_verification.strip()),
        "missing_data_or_permission": _redact_string_m3(missing_data_or_permission.strip()),
        "efficiency_notes": _redact_string_m3(efficiency_notes.strip()),
    }
    missing_dims = [name for name in FIVE_DIMENSIONS if not dimensions[name]]
    if missing_dims:
        raise ValueError(
            f"Behavior card {card_id!r} missing required non-empty dimensions: {missing_dims}"
        )

    clean_contract = _redact_string_m3(expected_controlbot_contract.strip())
    if not clean_contract:
        raise ValueError(
            f"Behavior card {card_id!r} requires a non-empty expected_controlbot_contract."
        )

    safe_conditions = _prepare_conditions(conditions)
    card = ReferenceBehaviorCard(
        card_id=card_id.strip(),
        case_id=case_id.strip(),
        source=source,
        status=status,
        unavailable_reason=None,
        bot_used=typed_bot,
        app_version=app_version,
        observed_at=observed_at or utc_now(),
        conditions=safe_conditions,
        discoverability=dimensions["discoverability"],
        state_transition=dimensions["state_transition"],
        independent_verification=dimensions["independent_verification"],
        missing_data_or_permission=dimensions["missing_data_or_permission"],
        efficiency_notes=dimensions["efficiency_notes"],
        expected_controlbot_contract=clean_contract,
    )
    violations = validate_reference_card(card)
    if violations:
        raise ValueError(f"Invalid ReferenceBehaviorCard {card.card_id!r}: {violations}")
    return card


def validate_reference_card(card: ReferenceBehaviorCard) -> list[str]:
    """Return a list of schema, scope, disclaimer, or redaction violations for a card."""
    violations: list[str] = []

    serialized = json.loads(card.model_dump_json())
    if _contains_unredacted_secret_m3(serialized):
        violations.append("unredacted_secret_detected")

    if card.bot_used is not None and card.bot_used not in ALLOWED_GROKBOT_BOTS:
        violations.append(f"forbidden_bot_used:{card.bot_used}")

    if not card.expected_controlbot_contract.strip():
        violations.append("missing_expected_controlbot_contract")

    if card.status == "REF_UNAVAILABLE":
        if not (card.unavailable_reason and card.unavailable_reason.strip()):
            violations.append("missing_unavailable_reason")
    else:
        if card.source == "ref_unavailable":
            violations.append("source_ref_unavailable_requires_status_REF_UNAVAILABLE")
        if card.source == "grok_bot_app" and card.bot_used not in ALLOWED_GROKBOT_BOTS:
            violations.append("grok_bot_app_requires_main_or_test_bot")
        for dim in FIVE_DIMENSIONS:
            if not str(getattr(card, dim, "")).strip():
                violations.append(f"empty_dimension:{dim}")

    if "timing_comparability" not in card.conditions:
        violations.append("missing_condition:timing_comparability")
    if "privacy_scope" not in card.conditions:
        violations.append("missing_condition:privacy_scope")

    return violations


def save_reference_card(
    card: ReferenceBehaviorCard,
    cards_dir: Path,
    *,
    repo_root: Path | None = None,
) -> Path:
    """Validate and atomically persist a ReferenceBehaviorCard JSON artifact."""
    safe_dir = assert_safe_mutation_path(cards_dir, repo_root=repo_root)
    _validate_card_id(card.card_id)
    violations = validate_reference_card(card)
    if violations:
        raise ValueError(f"Cannot save invalid card {card.card_id!r}: {violations}")

    payload = json.loads(card.model_dump_json())
    if _contains_unredacted_secret_m3(payload):
        raise ValueError(f"Refusing to save unredacted secret in card {card.card_id!r}.")

    safe_dir.mkdir(parents=True, exist_ok=True)
    resolved_dir = safe_dir.resolve()
    out_path = (resolved_dir / f"{card.card_id}.json").resolve()
    if out_path.parent != resolved_dir:
        raise ValueError(
            f"Invalid card_id {card.card_id!r}: resolved path escapes cards directory."
        )
    tmp_path = out_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp_path.replace(out_path)
    return out_path


def load_reference_cards(cards_dir: Path, *, strict: bool = True) -> list[ReferenceBehaviorCard]:
    """Load and validate all `*.json` ReferenceBehaviorCard files from `cards_dir`."""
    if not cards_dir.is_dir():
        return []
    cards: list[ReferenceBehaviorCard] = []
    for path in sorted(cards_dir.glob("*.json")):
        card = ReferenceBehaviorCard.model_validate_json(path.read_text(encoding="utf-8"))
        if strict:
            violations = validate_reference_card(card)
            if violations:
                raise ValueError(f"Invalid ReferenceBehaviorCard at {path}: {violations}")
        cards.append(card)
    return cards


def compare_against_fixture_truth(
    *,
    card: ReferenceBehaviorCard,
    fixture_passed: bool,
    fixture_detail: str,
    reference_matches_fixture: bool | None = None,
) -> dict[str, Any]:
    """Resolve ControlBot pass/fail with synthetic fixture truth overriding external reference."""
    authoritative_passed = bool(fixture_passed)
    if card.status == "REF_UNAVAILABLE":
        verdict = "pass_local_fixture" if authoritative_passed else "fail_local_fixture"
        discrepancy = False
        action = "none" if authoritative_passed else "open_qa_failure_item"
    elif not authoritative_passed:
        verdict = "fail_controlbot_issue_opened"
        discrepancy = reference_matches_fixture is True
        action = "open_qa_failure_item"
    elif reference_matches_fixture is False:
        verdict = "pass_fixture_overrides_reference"
        discrepancy = True
        action = "trust_synthetic_fixture"
    else:
        verdict = "pass_parity_aligned"
        discrepancy = False
        action = "none"

    return {
        "case_id": card.case_id,
        "card_id": card.card_id,
        "truth_source": "synthetic_fixture",
        "reference_status": card.status,
        "reference_bot": card.bot_used,
        "authoritative_passed": authoritative_passed,
        "reference_discrepancy": discrepancy,
        "verdict": verdict,
        "action": action,
        "fixture_detail": _redact_string_m3(fixture_detail),
    }


def observe_grokbot_readonly(
    *,
    case_id: str,
    bot_name: str = "test",
    display: str | None = None,
    app_version: str | None = "1.3.0",
    expected_controlbot_contract: str | None = None,
) -> ReferenceBehaviorCard:
    """Safely enforce main/test boundary and return REF_UNAVAILABLE when live probe is omitted.

    Never reads `~/.config/Grok Bot`, cookies, auth tokens, or `app.asar`, and never clicks or
    mutates live X11 displays when running inside automated lab/test checks.
    """
    normalized_bot = _require_allowed_bot(bot_name)
    effective_display = (display if display is not None else os.environ.get("DISPLAY", "")).strip()
    if not effective_display:
        reason = (
            "Grok Bot live X11 display is absent in isolated lab environment; "
            "continuing deterministic local evaluation."
        )
    else:
        reason = (
            f"Live X11 interaction on {effective_display} is disabled in automated harness; "
            "use empirical verified cards or manual main/test observation."
        )
    return build_ref_unavailable_card(
        case_id=case_id,
        reason=reason,
        bot_used=normalized_bot,
        app_version=app_version,
        expected_controlbot_contract=expected_controlbot_contract,
        conditions={"display_checked": effective_display or "unset"},
    )


def build_m3_observed_reference_cards() -> list[ReferenceBehaviorCard]:
    """Build the 9 verified M3 Grok Bot v1.3.0 (`main`/`test` ONLY) & REF_UNAVAILABLE cards."""
    base_conditions: dict[str, Any] = {
        "backend_note": "Grok Bot runs on xAI cloud; latency is observational only",
        "observation_method": "passive_x11_main_and_test_only_no_config_or_asar_read",
    }

    cards: list[ReferenceBehaviorCard] = [
        build_reference_card(
            card_id="ref-cb01-simple-chat",
            case_id="CB-01",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Single-row bottom pill composer with placeholder 'Message test' (or contextual "
                "onboarding prompt); pink voice orb morphs to Up-Arrow Send button on text."
            ),
            state_transition=(
                "Return -> 150ms optimistic user bubble in bot accent color + timestamp -> "
                "1.1s bot avatar placeholder -> 2.6s 'Generating the reply' -> 5.0s 'Typing...' -> "
                "<=8.2s final bubble + synchronous sidebar preview update."
            ),
            independent_verification=(
                "Synthetic prompt 'Reply with exactly OK_M3_PROBE' produced exact string "
                "'OK_M3_PROBE' in assistant bubble and sidebar preview."
            ),
            missing_data_or_permission=(
                "Unanswered onboarding multiple-choice card smoothly collapses/dims when "
                "superseded by free-text user prompt."
            ),
            efficiency_notes=(
                "1 action (focus + Enter); TTFP=150.1ms UI / 2600ms server progress; "
                "total <=8.23s (cloud)."
            ),
            expected_controlbot_contract=(
                "ControlBot Studio CB-01 must render user message + visible progress + exact "
                "final reply across agy and controlbot_runtime (general chat lane), persist "
                "across reload, and update sidebar subtext without raw JSON/stack errors."
            ),
        ),
        build_reference_card(
            card_id="ref-cb03-cancel-reconnect",
            case_id="CB-03",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Grok Bot v1.3.0 short-reply composer reverted the send button to the voice orb "
                "during 'Generating the reply' with no visible Stop button."
            ),
            state_transition=(
                "ControlBot Studio improves on this reference by rendering a red Stop button "
                "(aria-label='Stop current generation') during activeTurn."
            ),
            independent_verification=(
                "Cancel must yield coherent terminal state, 0 post-cancel side effects, and "
                "SSE Last-Event-ID reconnect without duplicate message bubbles."
            ),
            missing_data_or_permission=(
                "If backend stream drops or run is interrupted, UI must show terminal "
                "interrupted/cancelled state with retry option."
            ),
            efficiency_notes=(
                "1 click to Stop; ControlBot Studio should preserve single-row composer so "
                "Stop + Send remain aligned even when Inspector is open."
            ),
            expected_controlbot_contract=(
                "Stop button visible during any active turn, 0 post-cancel workspace "
                "writes/messages, and clean deduped SSE reconnect."
            ),
        ),
        build_reference_card(
            card_id="ref-cb04-roster-navigation",
            case_id="CB-04",
            source="grok_bot_app",
            status="observed",
            bot_used="main",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Main bot ('Grok Bot') is pinned prominently at top-center of sidebar with orange "
                "star badge; Search and '+' New buttons sit in sidebar header; active thread "
                "shows pill/rounded-square highlight."
            ),
            state_transition=(
                "Selecting 'main' vs 'test' switches center header pill, transcript, and composer "
                "placeholder ('Message test' vs 'Type your answer...') synchronously."
            ),
            independent_verification=(
                "Observed read-only switching between 'Grok Bot' (main) and 'test' preserving "
                "distinct thread transcripts and active indicator."
            ),
            missing_data_or_permission=(
                "Hidden/empty states must remain navigable without leaking cross-bot context."
            ),
            efficiency_notes=(
                "1 click to switch bots; ControlBot Studio adds Cmd+K / Cmd+1..9 keyboard jumping."
            ),
            expected_controlbot_contract=(
                "ControlBot Studio must support create/rename/hide/unhide bots & sections, "
                "thread switching without context bleed, and @mention routing in group channels."
            ),
        ),
        build_reference_card(
            card_id="ref-cb05-attachments-teach-library",
            case_id="CB-05",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Composer '+' popover consolidates 'Attach files' and 'Teach a task' in 1 click "
                "from chat; bot header pill opens right drawer containing 'Activity' | 'Library'."
            ),
            state_transition=(
                "Clicking '+' opens floating menu above composer; Escape closes it cleanly "
                "without clearing draft."
            ),
            independent_verification=(
                "ControlBot Studio requires 1 click for Paperclip attach, 1-2 clicks for Library, "
                "and 2-3 clicks to reach 'Teach a task' under Computer -> Screen."
            ),
            missing_data_or_permission=(
                "Invalid/oversized attachments or empty library states show clear inline guidance."
            ),
            efficiency_notes=(
                "1 click to access attach/teach menu in Grok Bot; Escape closes overlay."
            ),
            expected_controlbot_contract=(
                "Attachments upload/persist per thread, Pages/artifacts save & filter in Library "
                "without cross-thread leakage."
            ),
        ),
        build_reference_card(
            card_id="ref-cb06-computer-takeover",
            case_id="CB-06",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Bot header pill ('test') -> 'Bot's computer' card shows live sleep state "
                "('Asleep' / 'Awake') and preview thumbnail; clicking launches takeover."
            ),
            state_transition=(
                "'Asleep' card click -> 'Starting desktop' spinner (~0.8s) -> live desktop "
                "(~2.5s) with bottom floating pill ('Watching' | 'Take control') and collapse btn."
            ),
            independent_verification=(
                "Verified full wake-and-collapse cycle on 'test' bot returning cleanly to "
                "chat + drawer."
            ),
            missing_data_or_permission=(
                "When VNC/browser is stopped in ControlBot Studio, show explicit 'Asleep' or "
                "'Stopped' status + Launch/Retry without misleading 'bot@cloud' label when local."
            ),
            efficiency_notes=(
                "2 clicks from chat to live desktop; ~2.5s cold wake on Grok Bot cloud VM."
            ),
            expected_controlbot_contract=(
                "Live connection badge, Watching vs Take control lease (409 on conflict), "
                "handback, local PTY output, and panel<->backend state coherence."
            ),
        ),
        build_reference_card(
            card_id="ref-cb07-approvals-hitl",
            case_id="CB-07",
            source="grok_bot_app",
            status="observed",
            bot_used="main",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Inline structured decision card in main bot thread presenting explicit binary "
                "options ('A Yes, stop the leftovers' / 'B No, leave them running') before action."
            ),
            state_transition=(
                "Pending decision halts action until user selects A/B; unanswered cards "
                "dim/collapse if superseded."
            ),
            independent_verification=(
                "Observed read-only in 'main' bot thread; ControlBot Studio implements "
                "ApprovalCard / EditableDraftCard / SecureFormCard."
            ),
            missing_data_or_permission=(
                "Denying or omitting approval produces 0 side effects; replay must return 409."
            ),
            efficiency_notes="1 click to approve or deny inline without leaving chat.",
            expected_controlbot_contract=(
                "Simulated effect pauses pre-execution; deny=0 effects, allow=1 idempotent "
                "effect, duplicate replay=409, visible error recovery."
            ),
        ),
        build_reference_card(
            card_id="ref-cb08-settings-routines-voice",
            case_id="CB-08",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            app_version="1.3.0",
            conditions=base_conditions,
            discoverability=(
                "Right drawer ('test' pill) surfaces 'Suggested' ('Create a routine >', "
                "'Add to meeting >') and 'Voice chat' ('Voice', 'Language') in 1 click; "
                "'Connect apps' sits in sidebar footer."
            ),
            state_transition=(
                "Drawer opens smoothly at ~335px width without breaking single-row composer."
            ),
            independent_verification=(
                "ControlBot Studio exposes SettingsDialog (5 tabs), MemoryModal, and "
                "BotDetailsTab (Routines/Skills/Vault) with reload persistence on messages."
            ),
            missing_data_or_permission=(
                "Disabled/paused routines display explicit 'Paused' badge and respect scope."
            ),
            efficiency_notes=(
                "1-2 clicks to reach Routines/Settings; modal Tab trap works, Escape focus "
                "restoration needs improvement for keyboard shortcuts."
            ),
            expected_controlbot_contract=(
                "Settings persist across reload, 5-scope memory isolation holds, synthetic "
                "routine creates RoutineRun history, keyboard modals restore focus cleanly."
            ),
        ),
        build_ref_unavailable_card(
            card_id="ref-cb02-price-query-ref-unavailable",
            case_id="CB-02",
            reason=(
                "CB-VALVE-104 synthetic catalog fixture is a local loopback lab catalog not hosted "
                "on public internet for Grok Bot remote cloud browser (Megaplan §2). Ground truth "
                "derives from src/qa/fixtures/cb_valve_104."
            ),
            bot_used=None,
            app_version="1.3.0",
            expected_controlbot_contract=(
                "Return exact current price USD 129.50 vs prior USD 154.00, SKU, currency, and "
                "expected URL from local CB-VALVE-104 fixture; report uncertainty on nonexistent "
                "or 2-match SKUs."
            ),
            conditions=base_conditions,
        ),
        build_ref_unavailable_card(
            card_id="ref-cb11-cb13-local-industrial-n3-ref-unavailable",
            case_id="CB-11",
            reason=(
                "Industrial OT/SCADA/CMMS read-only reconciliation (CB-11) and zero-egress Linux "
                "local LLM N3 certification (CB-13) are local/offline profiles unavailable in "
                "Grok Bot cloud client (Megaplan §2-§3, §6)."
            ),
            bot_used=None,
            app_version="1.3.0",
            expected_controlbot_contract=(
                "CB-11 verifies read-only Pump 34 + homonymous facility provenance/contradictions "
                "from local SCADA/CMMS fixtures; CB-13 passes verify_n3_linux.sh, "
                "src.n3_probe --strict, and zero-egress local LLM execution."
            ),
            conditions=base_conditions,
        ),
    ]
    return cards


def emit_m3_reference_cards(cards_dir: Path | None = None) -> list[Path]:
    """Generate and persist all 9 M3 verified reference cards into `cards_dir`."""
    target_dir = cards_dir if cards_dir is not None else _DEFAULT_CARDS_DIR
    written: list[Path] = []
    for card in build_m3_observed_reference_cards():
        written.append(save_reference_card(card, target_dir, repo_root=_REPO_ROOT))
    return written


__all__ = [
    "FIVE_DIMENSIONS",
    "HARDWARE_ENV_DISCLAIMER",
    "build_m3_observed_reference_cards",
    "build_ref_unavailable_card",
    "build_reference_card",
    "compare_against_fixture_truth",
    "emit_m3_reference_cards",
    "load_reference_cards",
    "observe_grokbot_readonly",
    "save_reference_card",
    "validate_reference_card",
]
