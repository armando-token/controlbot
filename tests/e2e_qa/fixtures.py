"""Dynamic synthetic fixtures and independent evaluators for opaque-box E2E QA tests."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from html import escape
from pathlib import Path
from typing import Literal

ALLOWED_GROK_BOTS: frozenset[str] = frozenset({"main", "test"})


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


def _to_decimal_price(raw: Decimal | str) -> Decimal:
    val = raw if isinstance(raw, Decimal) else Decimal(str(raw))
    return val.quantize(Decimal("0.01"))


def build_cb_valve_104_catalog(
    *,
    sku: str = "CB-VALVE-104",
    currency: str = "USD",
    seed: int | None = None,
    current_price: Decimal | str | None = None,
    prior_price: Decimal | str | None = None,
) -> ValveCatalogFixture:
    """Build a dynamic CB-VALVE-104 catalog with separate current and prior price records."""
    rng = random.Random(seed if seed is not None else time.time_ns())
    if current_price is None:
        cents = rng.randint(10500, 19900)
        resolved_current = Decimal(cents) / Decimal(100)
    else:
        resolved_current = _to_decimal_price(current_price)

    if prior_price is None:
        delta_cents = rng.randint(1200, 4500)
        resolved_prior = (resolved_current + (Decimal(delta_cents) / Decimal(100))).quantize(
            Decimal("0.01")
        )
    else:
        resolved_prior = _to_decimal_price(prior_price)

    if resolved_current == resolved_prior:
        resolved_prior = (resolved_current + Decimal("10.00")).quantize(Decimal("0.01"))

    slug = sku.lower()
    active_record = CatalogRecord(
        record_id="rec-active-01",
        sku=sku,
        title="ControlBot Industrial Valve 104",
        price=resolved_current,
        currency=currency,
        status="current",
        effective_date="2026-11-01",
        source_url=f"/catalog/valves/{slug}",
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
        source_url=f"/catalog/archive/{slug}-prior",
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
    return ValveCatalogFixture(
        fixture_version=f"cb-valve-104-v{rng.randint(1000, 9999)}",
        prompt_es=f"Busca el precio vigente de {sku} y dime en qué página lo encontraste",
        sku=sku,
        active_record=active_record,
        prior_record=prior_record,
        records=(active_record, prior_record),
        ambiguous_query=f"{sku} variant",
        ambiguous_matches=(ambiguous_a, ambiguous_b),
        nonexistent_sku="CB-VALVE-999-MISSING",
    )


@dataclass(frozen=True)
class CB09CsvSample:
    """Single CSV-to-JSON independent evaluation sample."""

    name: str
    csv_text: str
    expected_rows: tuple[dict[str, str], ...] | None
    expect_error: bool
    description: str


@dataclass(frozen=True)
class CB09SampleResult:
    """Outcome of running a candidate CSV converter on one CB-09 sample."""

    name: str
    passed: bool
    returncode: int
    detail: str


@dataclass(frozen=True)
class CB09EvalReport:
    """Aggregate report from the independent CB-09 CSV-to-JSON evaluator."""

    passed: bool
    sample_results: tuple[CB09SampleResult, ...]
    project_tests_passed: bool | None = None
    project_tests_output: str = ""


def build_cb09_csv_samples() -> tuple[CB09CsvSample, ...]:
    """Return adversarial CSV edge-case samples for CB-09 converter evaluation."""
    return (
        CB09CsvSample(
            name="empty_lines",
            csv_text="sku,name,qty\n\nCB-1,Valve,4\n   \nCB-2,Gauge,9\n\n",
            expected_rows=(
                {"sku": "CB-1", "name": "Valve", "qty": "4"},
                {"sku": "CB-2", "name": "Gauge", "qty": "9"},
            ),
            expect_error=False,
            description="Header + rows separated by empty and whitespace-only lines.",
        ),
        CB09CsvSample(
            name="quoted_fields",
            csv_text=(
                'sku,name,notes\n'
                'CB-10,"Valve, High-P","Sensor ""A1"""\n'
                'CB-11,"Line1\nLine2","Ok"\n'
            ),
            expected_rows=(
                {"sku": "CB-10", "name": "Valve, High-P", "notes": 'Sensor "A1"'},
                {"sku": "CB-11", "name": "Line1\nLine2", "notes": "Ok"},
            ),
            expect_error=False,
            description="Quoted commas, escaped double-quotes, and embedded newlines.",
        ),
        CB09CsvSample(
            name="invalid_malformed",
            csv_text='sku,name,qty\nCB-20,"Unterminated quote\nONLY_ONE_COL\n',
            expected_rows=None,
            expect_error=True,
            description="Malformed row width + unterminated quote must fail with non-zero exit.",
        ),
        CB09CsvSample(
            name="utf8_and_whitespace",
            csv_text="sku,name,qty\nCB-34,Válvula Nº 34,12\n",
            expected_rows=({"sku": "CB-34", "name": "Válvula Nº 34", "qty": "12"},),
            expect_error=False,
            description="UTF-8 accented Spanish characters preserved cleanly.",
        ),
    )


def evaluate_csv_to_json_converter(
    converter_cmd: Sequence[str],
    *,
    work_dir: Path,
    test_cmd: Sequence[str] | None = None,
    timeout_s: float = 30.0,
) -> CB09EvalReport:
    """Independently run and validate a CB-09 CSV-to-JSON converter and optional tests."""
    work_dir.mkdir(parents=True, exist_ok=True)
    samples = build_cb09_csv_samples()
    results: list[CB09SampleResult] = []

    for sample in samples:
        csv_path = work_dir / f"{sample.name}.csv"
        out_path = work_dir / f"{sample.name}.json"
        csv_path.write_text(sample.csv_text, encoding="utf-8")
        if out_path.exists():
            out_path.unlink()

        proc = subprocess.run(
            [*converter_cmd, str(csv_path), str(out_path)],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if sample.expect_error:
            ok = proc.returncode != 0
            detail = (
                "Rejected malformed CSV cleanly."
                if ok
                else "Converter exited 0 on malformed CSV!"
            )
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=ok,
                    returncode=proc.returncode,
                    detail=detail,
                )
            )
            continue

        if proc.returncode != 0:
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=False,
                    returncode=proc.returncode,
                    detail=f"Non-zero exit {proc.returncode}: {proc.stderr.strip()}",
                )
            )
            continue

        raw_json = (
            out_path.read_text(encoding="utf-8") if out_path.is_file() else proc.stdout
        )
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=False,
                    returncode=proc.returncode,
                    detail=f"Invalid JSON output: {exc}",
                )
            )
            continue

        expected_list = list(sample.expected_rows or ())
        ok = parsed == expected_list
        detail = (
            "Exact row match."
            if ok
            else f"Row mismatch: got {parsed!r}, expected {expected_list!r}"
        )
        results.append(
            CB09SampleResult(
                name=sample.name,
                passed=ok,
                returncode=proc.returncode,
                detail=detail,
            )
        )

    project_tests_passed: bool | None = None
    project_tests_output = ""
    if test_cmd is not None:
        test_proc = subprocess.run(
            list(test_cmd),
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        project_tests_passed = test_proc.returncode == 0
        project_tests_output = (test_proc.stdout + "\n" + test_proc.stderr).strip()

    all_samples_ok = all(r.passed for r in results)
    overall_ok = all_samples_ok and (project_tests_passed is not False)
    return CB09EvalReport(
        passed=overall_ok,
        sample_results=tuple(results),
        project_tests_passed=project_tests_passed,
        project_tests_output=project_tests_output,
    )


@dataclass(frozen=True)
class CB10DeliverableSpec:
    """Single deliverable contract for CB-10 two-agent collaboration."""

    deliverable_id: str
    rel_path: str
    assigned_agent: Literal["agent_alpha", "agent_beta"]
    description: str
    required_symbols: tuple[str, ...]


@dataclass(frozen=True)
class CB10ProjectSpec:
    """Synthetic 3-deliverable multi-file project spec for CB-10."""

    project_name: str
    agents: tuple[str, str]
    deliverables: tuple[CB10DeliverableSpec, CB10DeliverableSpec, CB10DeliverableSpec]
    build_command: tuple[str, ...]
    test_command: tuple[str, ...]


def build_cb10_three_deliverables_spec() -> CB10ProjectSpec:
    """Build the 3-deliverable, 2-agent synthetic project contract for CB-10."""
    return CB10ProjectSpec(
        project_name="cb10_summary_pkg",
        agents=("agent_alpha", "agent_beta"),
        deliverables=(
            CB10DeliverableSpec(
                deliverable_id="D1",
                rel_path="src_pkg/calc.py",
                assigned_agent="agent_alpha",
                description="Core numeric summary computation helper.",
                required_symbols=("compute_summary",),
            ),
            CB10DeliverableSpec(
                deliverable_id="D2",
                rel_path="src_pkg/cli.py",
                assigned_agent="agent_beta",
                description="CLI entrypoint integrating compute_summary from agent_alpha.",
                required_symbols=("main", "compute_summary"),
            ),
            CB10DeliverableSpec(
                deliverable_id="D3",
                rel_path="tests/test_calc_cli.py",
                assigned_agent="agent_beta",
                description="End-to-end unit/CLI roundtrip tests.",
                required_symbols=("test_summary_cli_roundtrip",),
            ),
        ),
        build_command=(sys.executable, "-m", "compileall", "-q", "src_pkg"),
        test_command=(sys.executable, "-m", "pytest", "-q"),
    )


@dataclass(frozen=True)
class GrokBotReferenceCardSpec:
    """Differential Grok Bot behavior card restricted strictly to main/test bots."""

    card_id: str
    case_id: str
    bot_used: Literal["main", "test"]
    source: Literal["grok_bot_app", "grok_bot_docs", "ref_unavailable"]
    status: Literal["observed", "documented", "REF_UNAVAILABLE"]
    unavailable_reason: str | None
    app_version: str
    discoverability: str
    state_transition: str
    independent_verification: str
    missing_data_or_permission: str
    efficiency_notes: str
    expected_controlbot_contract: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "card_id": self.card_id,
            "case_id": self.case_id,
            "bot_used": self.bot_used,
            "source": self.source,
            "status": self.status,
            "unavailable_reason": self.unavailable_reason,
            "app_version": self.app_version,
            "discoverability": self.discoverability,
            "state_transition": self.state_transition,
            "independent_verification": self.independent_verification,
            "missing_data_or_permission": self.missing_data_or_permission,
            "efficiency_notes": self.efficiency_notes,
            "expected_controlbot_contract": self.expected_controlbot_contract,
        }


def build_grok_bot_reference_card(
    *,
    bot_name: str,
    case_id: str,
    available: bool = True,
    unavailable_reason: str | None = None,
    app_version: str = "1.3.0",
) -> GrokBotReferenceCardSpec:
    """Create a Grok Bot differential behavior card, strictly allowing ONLY main/test bots."""
    if bot_name not in ALLOWED_GROK_BOTS:
        raise ValueError(
            f"Forbidden Grok Bot name {bot_name!r}; ONLY {sorted(ALLOWED_GROK_BOTS)} allowed."
        )
    typed_bot: Literal["main", "test"] = "main" if bot_name == "main" else "test"
    if not available:
        return GrokBotReferenceCardSpec(
            card_id=f"ref-{case_id.lower()}-{typed_bot}-unavail",
            case_id=case_id,
            bot_used=typed_bot,
            source="ref_unavailable",
            status="REF_UNAVAILABLE",
            unavailable_reason=unavailable_reason or "Grok Bot reference session unavailable",
            app_version=app_version,
            discoverability="",
            state_transition="",
            independent_verification="",
            missing_data_or_permission="",
            efficiency_notes="",
            expected_controlbot_contract=(
                "Continue deterministic local evaluation and record REF_UNAVAILABLE."
            ),
        )
    return GrokBotReferenceCardSpec(
        card_id=f"ref-{case_id.lower()}-{typed_bot}",
        case_id=case_id,
        bot_used=typed_bot,
        source="grok_bot_app",
        status="observed",
        unavailable_reason=None,
        app_version=app_version,
        discoverability="Primary composer and thread actions discoverable in 1-2 clicks.",
        state_transition="Pending -> running -> terminal state persists cleanly across reload.",
        independent_verification="Response verified against synthetic fixture truth source.",
        missing_data_or_permission="Blocks unapproved action and reports missing context.",
        efficiency_notes="Low action count; observational timing separated from local run.",
        expected_controlbot_contract=(
            f"Parity contract for {case_id} verified independently on local fixture."
        ),
    )
