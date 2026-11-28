"""CB-02 scenario runner: dynamic CB-VALVE-104 Q&A, price updates, missing & ambiguous SKUs."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

import httpx

from src.qa.fixtures.cb_valve_104 import (
    ValveCatalogFixture,
    evaluate_valve_104_reply,
    load_or_build_cb_valve_104_catalog,
    serve_valve_catalog,
)
from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    TurnOutcome,
    _load_matching_reference_cards,
    finalize_scenario,
    run_coro_sync,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import measure_ux_action


def _query_catalog_http_and_format(base_url: str, sku: str, *, mode: str = "current") -> str:
    """Fetch `/index.json` + HTML page from live loopback catalog HTTP server."""
    with httpx.Client(base_url=base_url, timeout=5.0, trust_env=False) as client:
        idx_resp = client.get("/index.json")
        idx_resp.raise_for_status()
        records = idx_resp.json()

        if mode == "ambiguous":
            matches = [r for r in records if str(r.get("sku", "")).startswith(f"{sku}-")]
            if len(matches) >= 2:
                parts = [
                    f"{m['sku']} ({m['currency']} {m['price']} at {m['source_url']})"
                    for m in matches[:2]
                ]
                return f"Multiple matching variants found; please clarify: {', '.join(parts)}."
            return f"No ambiguous matches for {sku}."

        matching = [r for r in records if r.get("sku") == sku]
        current = [r for r in matching if r.get("status") == "current"]
        if not current:
            return f"No current catalog price found for {sku} (not found)."

        chosen = current[0]
        page_resp = client.get(str(chosen["source_url"]))
        page_resp.raise_for_status()
        html = page_resp.text
        price_m = re.search(r"data-price='([^']+)'", html)
        price_val = price_m.group(1) if price_m else str(chosen["price"])
        return (
            f"{chosen['sku']}: {chosen['currency']} {price_val} "
            f"(effective {chosen['effective_date']}, source {chosen['source_url']})"
        )


_CARD_PREFIX_PRICE_RE = re.compile(
    r"(?:USD|EUR|GBP|MXN|[$€£])\s*(\d+(?:\.\d{1,2})?)\b",
    re.IGNORECASE,
)
_CARD_SUFFIX_PRICE_RE = re.compile(
    r"\b(\d+(?:\.\d{1,2})?)\s*(?:USD|EUR|GBP|MXN)\b",
    re.IGNORECASE,
)
_CARD_DECIMAL_PRICE_RE = re.compile(r"\b(\d+\.\d{2})\b")
_CARD_FULL_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_CARD_REL_URL_RE = re.compile(r"(?:^|[\s'\"(])(/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*)")


def _extract_card_prices(text: str) -> list[Decimal]:
    matches: list[Decimal] = []
    for pattern in (_CARD_PREFIX_PRICE_RE, _CARD_SUFFIX_PRICE_RE, _CARD_DECIMAL_PRICE_RE):
        for raw in pattern.findall(text):
            matches.append(Decimal(raw).quantize(Decimal("0.01")))
    return matches


def _extract_card_urls(text: str) -> list[str]:
    paths: list[str] = []

    def _collect_full(match: re.Match[str]) -> str:
        paths.append(urlparse(match.group(0).rstrip(".,;)")).path or "/")
        return " "

    stripped_text = _CARD_FULL_URL_RE.sub(_collect_full, text)
    paths.extend(_CARD_REL_URL_RE.findall(stripped_text))
    return paths


def _check_reference_card_alignment(
    ctx: ScenarioContext,
    fixture: ValveCatalogFixture,
) -> None:
    """Detect whether an observed CB-02 reference card conflicts with synthetic fixture truth."""
    cards = _load_matching_reference_cards(
        case_id="CB-02",
        campaign_dir=ctx.campaign_dir,
        repo_root=ctx.repo_root,
        provided_cards=ctx.reference_cards,
    )

    active_price = fixture.active_record.price
    active_str = str(active_price)
    prior_str = str(fixture.prior_record.price)
    active_url = fixture.active_record.source_url

    for card in cards:
        if card.case_id != "CB-02" or card.status == "REF_UNAVAILABLE":
            continue
        iv = card.independent_verification
        contract = card.expected_controlbot_contract
        blob = f"{iv} {contract}"

        if (
            prior_str != active_str
            and prior_str in blob
            and active_str not in iv
        ):
            ctx.reference_matches_fixture = False
            return

        iv_prices = _extract_card_prices(iv)
        if any(p != active_price for p in iv_prices):
            ctx.reference_matches_fixture = False
            return

        contract_prices = _extract_card_prices(contract)
        if not iv_prices and contract_prices and active_price not in contract_prices:
            ctx.reference_matches_fixture = False
            return

        iv_urls = _extract_card_urls(iv)
        contract_urls = _extract_card_urls(contract)
        if any(u != active_url for u in iv_urls):
            ctx.reference_matches_fixture = False
            return
        if not iv_urls and any(u != active_url for u in contract_urls):
            ctx.reference_matches_fixture = False
            return

    ctx.reference_matches_fixture = True


async def _run_cb02_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "rag_catalog"
    fixture = load_or_build_cb_valve_104_catalog(ctx.campaign_dir)
    ctx.fixture_version = fixture.fixture_version
    _check_reference_card_alignment(ctx, fixture)

    with serve_valve_catalog(fixture) as (catalog_origin, cat_state):
        catalog_port = urlparse(catalog_origin).port
        assert catalog_port is not None

        if ctx.caps.is_live_agent_target:
            async with ctx.async_client(timeout=35.0) as aclient:
                prompt_1 = (
                    f"{fixture.prompt_es} CATALOG_BASE={catalog_origin} "
                    f"CATALOG_PORT={catalog_port} SKU={fixture.sku}"
                )

                async def _turn_1() -> TurnOutcome:
                    return await trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        prompt_1,
                        timeout=25.0,
                    )

                turn_1, timing = await measure_ux_action(_turn_1, actions_to_reach=1)
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.message_id = str(turn_1.user_message.get("id") or "")
                reply_1 = turn_1.reply_text
                ok_1, assertions_1, detail_1 = evaluate_valve_104_reply(
                    reply_1, fixture, mode="current"
                )
                ctx.assertions.update({f"initial_{k}": v for k, v in assertions_1.items()})
                if not ok_1:
                    ctx.error_notes.append(detail_1)
                    ctx.evidence = {
                        "fixture_version": fixture.fixture_version,
                        "expected_active_price": str(fixture.active_record.price),
                        "expected_source_url": fixture.active_record.source_url,
                        "prior_price": str(fixture.prior_record.price),
                        "reply_1": reply_1,
                    }
                    ctx.clarity_notes = detail_1
                    return

                # Live price update check (same SKU, new dynamic price)
                new_price = (fixture.active_record.price + Decimal("17.35")).quantize(
                    Decimal("0.01")
                )
                updated_fixture = fixture.apply_price_update(new_price, effective_date="2026-11-29")
                cat_state.update(updated_fixture)
                prompt_2 = (
                    f"Re-check {updated_fixture.sku} price update "
                    f"CATALOG_BASE={catalog_origin} CATALOG_PORT={catalog_port} "
                    f"SKU={updated_fixture.sku}"
                )
                turn_2 = await trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    prompt_2,
                    timeout=25.0,
                )
                reply_2 = turn_2.reply_text
                ok_2, assertions_2, detail_2 = evaluate_valve_104_reply(
                    reply_2, updated_fixture, mode="current"
                )
                ctx.assertions.update({f"updated_{k}": v for k, v in assertions_2.items()})
                if not ok_2:
                    ctx.error_notes.append(detail_2)

                # Nonexistent SKU abstention check
                prompt_missing = (
                    f"Busca el precio vigente de {fixture.nonexistent_sku} en el catálogo "
                    f"CATALOG_BASE={catalog_origin} CATALOG_PORT={catalog_port} "
                    f"MISSING_SKU={fixture.nonexistent_sku}"
                )
                turn_missing = await trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    prompt_missing,
                    timeout=25.0,
                )
                reply_missing = turn_missing.reply_text
                ok_miss, assertions_miss, detail_miss = evaluate_valve_104_reply(
                    reply_missing, fixture, mode="missing"
                )
                ctx.assertions.update({f"missing_{k}": v for k, v in assertions_miss.items()})
                if not ok_miss:
                    ctx.error_notes.append(detail_miss)

                # Two-match ambiguity clarification check
                prompt_ambig = (
                    f"Busca el precio de {fixture.ambiguous_query} y aclara si hay "
                    f"múltiples variantes CATALOG_BASE={catalog_origin} "
                    f"CATALOG_PORT={catalog_port} AMBIGUOUS_QUERY={fixture.ambiguous_query}"
                )
                turn_ambig = await trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    prompt_ambig,
                    timeout=25.0,
                )
                reply_ambig = turn_ambig.reply_text
                ok_ambig, assertions_ambig, detail_ambig = evaluate_valve_104_reply(
                    reply_ambig, fixture, mode="ambiguous"
                )
                ctx.assertions.update({f"ambiguous_{k}": v for k, v in assertions_ambig.items()})
                if not ok_ambig:
                    ctx.error_notes.append(detail_ambig)

                ctx.evidence = {
                    "fixture_version": fixture.fixture_version,
                    "active_price": str(fixture.active_record.price),
                    "currency": fixture.active_record.currency,
                    "source_url": fixture.active_record.source_url,
                    "updated_price": str(updated_fixture.active_record.price),
                    "reply_1": reply_1,
                    "reply_2": reply_2,
                    "reply_missing": reply_missing,
                    "reply_ambig": reply_ambig,
                }
                ctx.clarity_notes = detail_1 if not ctx.error_notes else "; ".join(ctx.error_notes)
        else:
            # Verify Studio target reachability + bots API alongside dynamic HTTP catalog evaluation
            with ctx.sync_client() as client:
                r_bots = client.get("/api/v1/bots")
                ctx.add_request_id(r_bots)
                ctx.assertions["studio_bots_api_200"] = r_bots.status_code == 200

            async def _eval_catalog() -> tuple[str, str, str, str, ValveCatalogFixture]:
                r1 = _query_catalog_http_and_format(catalog_origin, fixture.sku, mode="current")
                new_price = (fixture.active_record.price + Decimal("17.35")).quantize(
                    Decimal("0.01")
                )
                upd = fixture.apply_price_update(new_price, effective_date="2026-11-29")
                cat_state.update(upd)
                r2 = _query_catalog_http_and_format(catalog_origin, upd.sku, mode="current")
                r_missing = _query_catalog_http_and_format(
                    catalog_origin, fixture.nonexistent_sku, mode="current"
                )
                r_ambig = _query_catalog_http_and_format(
                    catalog_origin, fixture.sku, mode="ambiguous"
                )
                return r1, r2, r_missing, r_ambig, upd

            (reply_1, reply_2, reply_missing, reply_ambig, updated_fixture), timing = (
                await measure_ux_action(_eval_catalog, actions_to_reach=1)
            )
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms

            ok_1, assertions_1, detail_1 = evaluate_valve_104_reply(
                reply_1, fixture, mode="current"
            )
            ok_2, assertions_2, detail_2 = evaluate_valve_104_reply(
                reply_2, updated_fixture, mode="current"
            )
            ok_miss, assertions_miss, detail_miss = evaluate_valve_104_reply(
                reply_missing, fixture, mode="missing"
            )
            ok_ambig, assertions_ambig, detail_ambig = evaluate_valve_104_reply(
                reply_ambig, fixture, mode="ambiguous"
            )

            ctx.assertions.update({f"initial_{k}": v for k, v in assertions_1.items()})
            ctx.assertions.update({f"updated_{k}": v for k, v in assertions_2.items()})
            ctx.assertions.update({f"missing_{k}": v for k, v in assertions_miss.items()})
            ctx.assertions.update({f"ambiguous_{k}": v for k, v in assertions_ambig.items()})

            for ok_flag, msg in (
                (ok_1, detail_1),
                (ok_2, detail_2),
                (ok_miss, detail_miss),
                (ok_ambig, detail_ambig),
            ):
                if not ok_flag:
                    ctx.error_notes.append(msg)

            ctx.evidence = {
                "fixture_version": fixture.fixture_version,
                "sku": fixture.sku,
                "active_price": str(fixture.active_record.price),
                "prior_price": str(fixture.prior_record.price),
                "currency": fixture.active_record.currency,
                "source_url": fixture.active_record.source_url,
                "updated_price": str(updated_fixture.active_record.price),
                "reply_1": reply_1,
                "reply_2": reply_2,
                "reply_missing": reply_missing,
                "reply_ambig": reply_ambig,
            }
            ctx.clarity_notes = detail_1 if not ctx.error_notes else "; ".join(ctx.error_notes)


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-02 scenario."""
    run_coro_sync(_run_cb02_async(ctx))
    return finalize_scenario(ctx)
