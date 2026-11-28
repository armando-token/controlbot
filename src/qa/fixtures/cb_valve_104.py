"""Dynamic CB-VALVE-104 catalog fixture, HTTP server, and independent reply evaluator."""

from __future__ import annotations

import contextlib
import http.server
import json
import random
import re
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from html import escape
from pathlib import Path
from typing import Any, Literal

from src.qa.isolation import alloc_ephemeral_port

_ABSTENTION_RE = re.compile(
    r"(no\s+(?:current|catalog|price|matching|record|item)|"
    r"not\s+found|no\s+se\s+encontr|missing|does\s+not\s+exist|"
    r"unknown|unavailable|cannot\s+find|abstain|no\s+encontr[eé]|inexistente)",
    re.IGNORECASE,
)
_CLARIFICATION_RE = re.compile(
    r"(clarif|disambiguat|which\s+(?:variant|one|sku)|"
    r"please\s+(?:specify|choose|select|confirm)|choose\s+between|specify\s+which|"
    r"aclarar|especific|cu[aá]l\s+(?:variante|opci[oó]n))",
    re.IGNORECASE,
)
_SINGLE_VARIANT_COMMIT_RE = re.compile(
    r"(?:"
    r"\b(?:i|we)\s+(?:selected|chose|picked|used|went\s+with|will\s+use)\b|"
    r"\b(?:using|selected|chosen|picked|defaulting\s+to|assuming|proceeding\s+with)\s+"
    r"(?:variant|option|sku|cb-valve-[a-z0-9-]+)|"
    r"\b(?:(?:i|we)\s+)?recommend(?:ed)?(?:\s+(?:using|choosing|selecting))?\s+"
    r"(?:the\s+)?(?:variant\s+|option\s+|sku\s+)?cb-valve-[a-z0-9-]+\b|"
    r"\brecommended\s+(?:variant|option|sku|price)\s*(?:is|:)\b|"
    r"\b(?:chosen|selected|default|definitive)\s+(?:variant|option|price)\b|"
    r"\bdefinitive\s+price\s+is\b"
    r")",
    re.IGNORECASE,
)
_FABRICATED_PRICE_RE = re.compile(
    r"(?:"
    r"(?:USD|EUR|GBP|MXN)\s*\d+(?:[.,]\d{1,2})?|"
    r"\b\d+(?:[.,]\d{1,2})?\s*(?:USD|EUR|GBP|MXN)\b|"
    r"[$€£]\s*\d+(?:[.,]\d{1,2})?|"
    r"\b\d+\.\d{2}\b"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CatalogRecord:
    """Single synthetic catalog pricing record (current or superseded)."""

    record_id: str
    sku: str
    title: str
    price: Decimal
    currency: str
    status: Literal["current", "superseded"]
    effective_date: str
    source_url: str
    notes: str = ""


@dataclass(frozen=True)
class ValveCatalogFixture:
    """Dynamic CB-VALVE-104 catalog fixture with separate current/prior records & ambiguity."""

    fixture_version: str
    prompt_es: str
    sku: str
    active_record: CatalogRecord
    prior_record: CatalogRecord
    records: tuple[CatalogRecord, ...]
    ambiguous_query: str
    ambiguous_matches: tuple[CatalogRecord, ...]
    nonexistent_sku: str

    def apply_price_update(
        self,
        new_price: Decimal | str,
        *,
        effective_date: str = "2026-11-28",
        source_url: str | None = None,
    ) -> ValveCatalogFixture:
        """Return an updated catalog keeping the same SKU and demoting the previous price."""
        parsed_price = _to_decimal_price(new_price)
        demoted = CatalogRecord(
            record_id=self.active_record.record_id,
            sku=self.active_record.sku,
            title=self.active_record.title,
            price=self.active_record.price,
            currency=self.active_record.currency,
            status="superseded",
            effective_date=self.active_record.effective_date,
            source_url=self.active_record.source_url,
            notes="Superseded by newer price revision",
        )
        updated_active = CatalogRecord(
            record_id=f"{self.active_record.record_id}-rev2",
            sku=self.sku,
            title=self.active_record.title,
            price=parsed_price,
            currency=self.active_record.currency,
            status="current",
            effective_date=effective_date,
            source_url=source_url or self.active_record.source_url,
            notes="Updated active price",
        )
        new_records = (
            updated_active,
            demoted,
            *(r for r in self.records if r.record_id != self.active_record.record_id),
        )
        return ValveCatalogFixture(
            fixture_version=f"{self.fixture_version}-upd",
            prompt_es=self.prompt_es,
            sku=self.sku,
            active_record=updated_active,
            prior_record=demoted,
            records=new_records,
            ambiguous_query=self.ambiguous_query,
            ambiguous_matches=self.ambiguous_matches,
            nonexistent_sku=self.nonexistent_sku,
        )

    def render_html_pages(self) -> dict[str, str]:
        """Render synthetic catalog HTML pages keyed by relative source_url."""
        pages: dict[str, str] = {}
        ordered_records = sorted(
            (*self.records, *self.ambiguous_matches),
            key=lambda rec: 1 if rec.status == "current" else 0,
        )
        for rec in ordered_records:
            pages[rec.source_url] = (
                "<!doctype html><html><head>"
                f"<title>{escape(rec.sku)} — {escape(rec.title)}</title>"
                "</head><body>"
                f"<h1>{escape(rec.title)}</h1>"
                f"<p data-sku='{escape(rec.sku)}'>SKU: {escape(rec.sku)}</p>"
                f"<p data-status='{escape(rec.status)}'>Status: {escape(rec.status)}</p>"
                f"<p data-price='{escape(str(rec.price))}'>"
                f"Price: {escape(rec.currency)} {escape(str(rec.price))}</p>"
                f"<p data-effective='{escape(rec.effective_date)}'>"
                f"Effective: {escape(rec.effective_date)}</p>"
                f"<p data-source='{escape(rec.source_url)}'>Source: {escape(rec.source_url)}</p>"
                "</body></html>"
            )
        return pages

    def to_json_records(self) -> list[dict[str, str]]:
        """Serialize all catalog records as JSON-safe dictionaries."""
        return [
            {
                "record_id": rec.record_id,
                "sku": rec.sku,
                "title": rec.title,
                "price": str(rec.price),
                "currency": rec.currency,
                "status": rec.status,
                "effective_date": rec.effective_date,
                "source_url": rec.source_url,
                "notes": rec.notes,
            }
            for rec in (*self.records, *self.ambiguous_matches)
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serialize fixture manifest compatible with `cb_valve_104.json`."""
        return {
            "fixture_version": self.fixture_version,
            "prompt_es": self.prompt_es,
            "sku": self.sku,
            "active_price": str(self.active_record.price),
            "prior_price": str(self.prior_record.price),
            "currency": self.active_record.currency,
            "source_url": self.active_record.source_url,
            "prior_source_url": self.prior_record.source_url,
            "nonexistent_sku": self.nonexistent_sku,
            "ambiguous_query": self.ambiguous_query,
            "records": self.to_json_records(),
        }


def _to_decimal_price(raw: Decimal | str | int | float) -> Decimal:
    try:
        val = raw if isinstance(raw, Decimal) else Decimal(str(raw))
    except InvalidOperation as exc:
        raise ValueError(f"Invalid catalog decimal price: {raw!r}") from exc
    return val.quantize(Decimal("0.01"))


def build_cb_valve_104_catalog(
    *,
    sku: str = "CB-VALVE-104",
    currency: str = "USD",
    seed: int | None = None,
    current_price: Decimal | str | None = None,
    prior_price: Decimal | str | None = None,
    source_url: str | None = None,
    prior_source_url: str | None = None,
    fixture_version: str | None = None,
    dynamic_random: bool = False,
) -> ValveCatalogFixture:
    """Build a dynamic CB-VALVE-104 catalog with separate current and prior price records."""
    rng = random.Random(seed if seed is not None else time.time_ns())
    if current_price is None:
        if seed is not None or dynamic_random:
            cents = rng.randint(10500, 19900)
            resolved_current = Decimal(cents) / Decimal(100)
        else:
            resolved_current = Decimal("129.50")
    else:
        resolved_current = _to_decimal_price(current_price)

    if prior_price is None:
        if seed is not None or dynamic_random or current_price is not None:
            if resolved_current == Decimal("129.50"):
                resolved_prior = Decimal("154.00")
            else:
                delta_cents = rng.randint(1200, 4500)
                resolved_prior = (
                    resolved_current + (Decimal(delta_cents) / Decimal(100))
                ).quantize(Decimal("0.01"))
        else:
            resolved_prior = Decimal("154.00")
    else:
        resolved_prior = _to_decimal_price(prior_price)

    if resolved_current == resolved_prior:
        resolved_prior = (resolved_current + Decimal("24.50")).quantize(Decimal("0.01"))

    slug = sku.lower()
    resolved_source_url = source_url or f"/catalog/valves/{slug}"
    resolved_prior_url = prior_source_url or f"/catalog/archive/{slug}-prior"

    active_record = CatalogRecord(
        record_id="rec-active-01",
        sku=sku,
        title="ControlBot Industrial Valve 104",
        price=resolved_current,
        currency=currency,
        status="current",
        effective_date="2026-11-01",
        source_url=resolved_source_url,
        notes="Current active offer",
    )
    prior_record = CatalogRecord(
        record_id="rec-prior-01",
        sku=sku,
        title="ControlBot Industrial Valve 104 (Legacy List)",
        price=resolved_prior,
        currency=currency,
        status="superseded",
        effective_date="2026-06-15",
        source_url=resolved_prior_url,
        notes="Prior list price superseded by current offer",
    )
    ambiguous_a = CatalogRecord(
        record_id="rec-ambig-a",
        sku=f"{sku}-A",
        title="ControlBot Industrial Valve 104 Brass Seat",
        price=(resolved_current + Decimal("5.00")).quantize(Decimal("0.01")),
        currency=currency,
        status="current",
        effective_date="2026-11-01",
        source_url=f"/catalog/valves/{slug}-a",
    )
    ambiguous_b = CatalogRecord(
        record_id="rec-ambig-b",
        sku=f"{sku}-B",
        title="ControlBot Industrial Valve 104 Stainless Seat",
        price=(resolved_current + Decimal("15.00")).quantize(Decimal("0.01")),
        currency=currency,
        status="current",
        effective_date="2026-11-01",
        source_url=f"/catalog/valves/{slug}-b",
    )
    version = fixture_version or f"cb-valve-104-v{rng.randint(1000, 9999)}"
    return ValveCatalogFixture(
        fixture_version=version,
        prompt_es=f"Busca el precio vigente de {sku} y dime en qué página lo encontraste",
        sku=sku,
        active_record=active_record,
        prior_record=prior_record,
        records=(active_record, prior_record),
        ambiguous_query=f"{sku} variant",
        ambiguous_matches=(ambiguous_a, ambiguous_b),
        nonexistent_sku="CB-VALVE-999-MISSING",
    )


def _record_from_dict(raw: dict[str, Any], *, default_currency: str = "USD") -> CatalogRecord:
    status_raw = str(raw.get("status") or "current").strip().lower()
    status_val: Literal["current", "superseded"] = (
        "superseded" if status_raw == "superseded" else "current"
    )
    return CatalogRecord(
        record_id=str(raw.get("record_id") or "rec-01"),
        sku=str(raw.get("sku") or "CB-VALVE-104"),
        title=str(raw.get("title") or "ControlBot Industrial Valve 104"),
        price=_to_decimal_price(raw["price"] if raw.get("price") is not None else "129.50"),
        currency=str(raw.get("currency") or default_currency),
        status=status_val,
        effective_date=str(raw.get("effective_date") or "2026-11-01"),
        source_url=str(raw.get("source_url") or "/catalog/valves/cb-valve-104"),
        notes=str(raw.get("notes") or ""),
    )


def load_or_build_cb_valve_104_catalog(
    campaign_dir: Path,
    *,
    seed: int | None = None,
) -> ValveCatalogFixture:
    """Load `campaign_dir/fixtures/cb_valve_104.json` if present, else build dynamically."""
    fixture_path = campaign_dir / "fixtures" / "cb_valve_104.json"
    if not fixture_path.is_file():
        return build_cb_valve_104_catalog(seed=seed)

    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {fixture_path}")

    sku = str(data.get("sku") or "CB-VALVE-104")
    currency = str(data.get("currency") or "USD")
    fixture_version = str(data.get("fixture_version") or "cb-valve-104-json")
    source_url = str(data.get("source_url") or f"/catalog/valves/{sku.lower()}")
    prior_source_url = str(data.get("prior_source_url") or f"/catalog/archive/{sku.lower()}-prior")

    raw_active = data.get("active_price")
    raw_prior = data.get("prior_price")

    raw_records = data.get("records")
    parsed_records: list[CatalogRecord] = []
    if isinstance(raw_records, list):
        for item in raw_records:
            if isinstance(item, dict):
                parsed_records.append(_record_from_dict(item, default_currency=currency))

    active_rec: CatalogRecord | None = next(
        (r for r in parsed_records if r.sku == sku and r.status == "current"),
        None,
    )
    prior_rec: CatalogRecord | None = next(
        (r for r in parsed_records if r.sku == sku and r.status == "superseded"),
        None,
    )
    ambiguous_recs = tuple(r for r in parsed_records if r.sku.startswith(f"{sku}-"))

    base = build_cb_valve_104_catalog(
        sku=sku,
        currency=currency,
        current_price=raw_active if raw_active is not None else (
            active_rec.price if active_rec is not None else None
        ),
        prior_price=raw_prior if raw_prior is not None else (
            prior_rec.price if prior_rec is not None else None
        ),
        source_url=active_rec.source_url if active_rec is not None else source_url,
        prior_source_url=prior_rec.source_url if prior_rec is not None else prior_source_url,
        fixture_version=fixture_version,
    )

    final_active = active_rec or base.active_record
    final_prior = prior_rec or base.prior_record
    parsed_core = [r for r in parsed_records if not r.sku.startswith(f"{sku}-")]
    if active_rec is None:
        parsed_core.insert(0, final_active)
    if prior_rec is None:
        parsed_core.append(final_prior)
    core_records = tuple(parsed_core)
    final_ambig: tuple[CatalogRecord, ...] = (
        ambiguous_recs if len(ambiguous_recs) >= 2 else base.ambiguous_matches
    )

    return ValveCatalogFixture(
        fixture_version=fixture_version,
        prompt_es=str(data.get("prompt_es") or base.prompt_es),
        sku=sku,
        active_record=final_active,
        prior_record=final_prior,
        records=core_records,
        ambiguous_query=str(data.get("ambiguous_query") or base.ambiguous_query),
        ambiguous_matches=final_ambig,
        nonexistent_sku=str(data.get("nonexistent_sku") or base.nonexistent_sku),
    )


class DynamicCatalogState:
    """Mutable holder for loopback HTTP catalog fixture serving."""

    def __init__(self, fixture: ValveCatalogFixture) -> None:
        self.lock = threading.Lock()
        self.fixture = fixture

    def update(self, fixture: ValveCatalogFixture) -> None:
        with self.lock:
            self.fixture = fixture

    def current(self) -> ValveCatalogFixture:
        with self.lock:
            return self.fixture


@contextlib.contextmanager
def serve_valve_catalog(
    initial: ValveCatalogFixture,
) -> Iterator[tuple[str, DynamicCatalogState]]:
    """Serve dynamic CB-VALVE-104 catalog HTML and JSON on an ephemeral loopback HTTP port."""
    state = DynamicCatalogState(initial)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            with state.lock:
                cur = state.fixture
                pages = cur.render_html_pages()
                records = cur.to_json_records()
            if path == "/index.json":
                payload = json.dumps(records, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path in pages:
                payload = pages[path].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_ephemeral_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


def _price_in_text(price: Decimal, text: str) -> bool:
    price_str = str(price)
    pattern = re.compile(rf"(?<![\d.,]){re.escape(price_str)}(?!\d|\.\d|,\d)")
    return pattern.search(text) is not None


def _build_url_pattern(url_path: str) -> re.Pattern[str]:
    if url_path.startswith("/"):
        return re.compile(
            rf"(?<![A-Za-z0-9_/-])(?:(?i:https?)://[A-Za-z0-9.\[\]:-]+)?{re.escape(url_path)}"
            r"(?![A-Za-z0-9_/-])"
        )
    return re.compile(rf"(?<![A-Za-z0-9_/-]){re.escape(url_path)}(?![A-Za-z0-9_/-])")


def evaluate_valve_104_reply(
    reply_text: str,
    fixture: ValveCatalogFixture,
    *,
    mode: Literal["current", "missing", "ambiguous"] = "current",
) -> tuple[bool, dict[str, bool], str]:
    """Independently evaluate a ControlBot reply against a dynamic ValveCatalogFixture."""
    text = reply_text.strip()
    if mode == "missing":
        abstained = _ABSTENTION_RE.search(text) is not None
        no_hallucinated_price = (
            not _price_in_text(fixture.active_record.price, text)
            and not _price_in_text(fixture.prior_record.price, text)
            and _FABRICATED_PRICE_RE.search(text) is None
        )
        assertions = {
            "non_empty_reply": bool(text),
            "abstains_on_missing_sku": abstained,
            "no_fabricated_price": no_hallucinated_price,
        }
        ok = all(assertions.values())
        detail = (
            f"Abstained cleanly for nonexistent SKU {fixture.nonexistent_sku}."
            if ok
            else f"Missing-SKU abstention failed: {assertions!r} in {text[:200]!r}"
        )
        return ok, assertions, detail

    if mode == "ambiguous":
        clarifies = _CLARIFICATION_RE.search(text) is not None
        matches = list(fixture.ambiguous_matches[:2])
        mentions_matches = all(m.sku.lower() in text.lower() for m in matches)
        commits_single = _SINGLE_VARIANT_COMMIT_RE.search(text) is not None
        if not commits_single and len(matches) >= 2 and matches[0].price != matches[1].price:
            has_p0 = _price_in_text(matches[0].price, text)
            has_p1 = _price_in_text(matches[1].price, text)
            if has_p0 != has_p1:
                commits_single = True
        assertions = {
            "non_empty_reply": bool(text),
            "requests_clarification": clarifies,
            "lists_ambiguous_variants": mentions_matches,
            "no_single_variant_selection": not commits_single,
        }
        ok = all(assertions.values())
        detail = (
            "Ambiguous SKU query returned 2-match clarification."
            if ok
            else f"Ambiguous-SKU clarification failed: {assertions!r} in {text[:200]!r}"
        )
        return ok, assertions, detail

    active_url = fixture.active_record.source_url
    prior_url = fixture.prior_record.source_url
    url_boundary = _build_url_pattern(active_url)
    prior_boundary = _build_url_pattern(prior_url)
    same_price = fixture.active_record.price == fixture.prior_record.price
    same_url = active_url == prior_url

    assertions = {
        "non_empty_reply": bool(text),
        "mentions_sku": fixture.sku.lower() in text.lower(),
        "mentions_currency": fixture.active_record.currency.lower() in text.lower(),
        "active_price_exact": _price_in_text(fixture.active_record.price, text),
        "active_source_url_exact": url_boundary.search(text) is not None,
        "rejects_prior_price": True
        if same_price
        else not _price_in_text(fixture.prior_record.price, text),
        "rejects_prior_source_url": True if same_url else prior_boundary.search(text) is None,
    }
    ok = all(assertions.values())
    if ok:
        detail = (
            f"Matched active {fixture.sku} price {fixture.active_record.currency} "
            f"{fixture.active_record.price} at {active_url}."
        )
    else:
        failed = [k for k, v in assertions.items() if not v]
        detail = (
            f"CB-VALVE-104 reply failed {failed}: expected {fixture.active_record.currency} "
            f"{fixture.active_record.price} at {active_url}, got {text[:240]!r}"
        )
    return ok, assertions, detail


__all__ = [
    "CatalogRecord",
    "DynamicCatalogState",
    "ValveCatalogFixture",
    "build_cb_valve_104_catalog",
    "evaluate_valve_104_reply",
    "load_or_build_cb_valve_104_catalog",
    "serve_valve_catalog",
]
