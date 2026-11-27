"""Tier-5 adversarial unit tests (Finding 3: OOXML Excel formula evaluator)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from src.adapters.office_excel import ExcelCellSpec, ExcelSheetSpec, OfficeExcelBuilder
from src.adapters.web_search import EgressBlockedError, EgressGuard
from src.contracts.envelope import VerdictState
from src.engine.verifiers.excel import SpreadsheetVerifier

pytestmark = [pytest.mark.n1, pytest.mark.tier5]


def test_ooxml_evaluator_quoted_sheet_names_with_spaces_hyphens_and_apostrophes(
    tmp_path: Path,
) -> None:
    xlsx_path = tmp_path / "quoted_sheets.xlsx"
    builder = OfficeExcelBuilder()
    builder.build_workbook(
        sheets=[
            ExcelSheetSpec(
                name="Cost Sheet",
                headers=("Cost",),
                rows=((10,), (20,)),
            ),
            ExcelSheetSpec(
                name="Q1-2026",
                headers=("Qty",),
                rows=((15,),),
            ),
            ExcelSheetSpec(
                name="O'Brien Sheet",
                headers=("Fee", "Tax"),
                rows=((50, 5), (25, 2.5)),
            ),
            ExcelSheetSpec(
                name="2026:Q1!",
                headers=("Val",),
                rows=((7,),),
            ),
            ExcelSheetSpec(
                name="Summary",
                headers=("Metric", "Value"),
                rows=(("SumCost", None),),
                formula_cells=(
                    ExcelCellSpec(
                        row=2,
                        col=2,
                        value=30,
                        formula="=SUM('Cost Sheet'!A2:A3)",
                    ),
                    ExcelCellSpec(
                        row=3,
                        col=2,
                        value=30,
                        formula="='Cost Sheet'!A2 + 'Cost Sheet'!A3",
                    ),
                    ExcelCellSpec(
                        row=4,
                        col=2,
                        value=30,
                        formula="='Q1-2026'!A2 * 2",
                    ),
                    ExcelCellSpec(
                        row=5,
                        col=2,
                        value=82.5,
                        formula="=SUM('O''Brien Sheet'!A2:B3)",
                    ),
                    ExcelCellSpec(
                        row=6,
                        col=2,
                        value=50,
                        formula="='O''Brien Sheet'!A2",
                    ),
                    ExcelCellSpec(
                        row=7,
                        col=2,
                        value=14,
                        formula="='2026:Q1!'!A2 * 2",
                    ),
                ),
            ),
        ],
        output_path=xlsx_path,
    )

    report = SpreadsheetVerifier().verify(
        xlsx_path,
        expected_totals={
            "'Summary'!B2": 30.0,
            "Summary!B5": 82.5,
            "Summary!B7": 14.0,
        },
        force_ooxml_evaluator=True,
    )
    assert report.recalc_engine == "ooxml_evaluator"
    assert report.passed is True, f"Unexpected verification errors: {report.errors}"
    assert report.verdict == VerdictState.VERIFIED
    assert report.formulas_total == 6
    assert report.formulas_ok == 6
    assert report.evaluated_values["Summary!B2"] == 30.0
    assert report.evaluated_values["Summary!B3"] == 30.0
    assert report.evaluated_values["Summary!B4"] == 30.0
    assert report.evaluated_values["Summary!B5"] == 82.5
    assert report.evaluated_values["Summary!B6"] == 50
    assert report.evaluated_values["Summary!B7"] == 14.0


def test_ooxml_evaluator_percentage_literals_and_blank_cell_coercion(
    tmp_path: Path,
) -> None:
    xlsx_path = tmp_path / "pct_and_blank.xlsx"
    builder = OfficeExcelBuilder()
    builder.build_workbook(
        sheets=[
            ExcelSheetSpec(
                name="Sheet1",
                headers=("Input", "Output"),
                rows=((None, None), (25, None)),
                formula_cells=(
                    ExcelCellSpec(row=2, col=2, value=100, formula="=IF(A2=0, 100, 200)"),
                    ExcelCellSpec(row=3, col=2, value=100, formula="=IF(0=A2, 100, 200)"),
                    ExcelCellSpec(row=4, col=2, value=10, formula='=IF(A2="", 10, 20)'),
                    ExcelCellSpec(row=5, col=2, value=2, formula="=IF(A2<>0, 1, 2)"),
                    ExcelCellSpec(row=6, col=2, value=20, formula="=10% * 200"),
                    ExcelCellSpec(row=7, col=2, value=20, formula="=200 * 10%"),
                    ExcelCellSpec(row=8, col=2, value=-0.1, formula="=-10%"),
                    ExcelCellSpec(row=9, col=2, value=15, formula="=(10 + 5)% * 100"),
                    ExcelCellSpec(row=10, col=2, value=0.25, formula="=A3%"),
                ),
            ),
        ],
        output_path=xlsx_path,
    )

    report = SpreadsheetVerifier().verify(
        xlsx_path,
        expected_totals={
            "Sheet1!B2": 100.0,
            "Sheet1!B6": 20.0,
            "Sheet1!B9": 15.0,
            "Sheet1!B10": 0.25,
        },
        force_ooxml_evaluator=True,
    )
    assert report.recalc_engine == "ooxml_evaluator"
    assert report.passed is True, f"Unexpected verification errors: {report.errors}"
    assert report.verdict == VerdictState.VERIFIED
    assert report.formulas_total == 9
    assert report.formulas_ok == 9
    assert report.evaluated_values["Sheet1!B2"] == 100
    assert report.evaluated_values["Sheet1!B3"] == 100
    assert report.evaluated_values["Sheet1!B4"] == 10
    assert report.evaluated_values["Sheet1!B5"] == 2
    assert abs(float(report.evaluated_values["Sheet1!B6"]) - 20.0) < 1e-9
    assert abs(float(report.evaluated_values["Sheet1!B7"]) - 20.0) < 1e-9
    assert abs(float(report.evaluated_values["Sheet1!B8"]) - (-0.1)) < 1e-9
    assert abs(float(report.evaluated_values["Sheet1!B9"]) - 15.0) < 1e-9
    assert abs(float(report.evaluated_values["Sheet1!B10"]) - 0.25) < 1e-9


@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://localhost./",
        "http://LOCALHOST./",
        "https://localhost.:8080/api",
        "http://foo.localhost/",
        "http://sub.foo.localhost./",
        "http://localhost.localdomain./",
        "http://sub.localhost.localdomain/",
        "http://./",
    ],
)
def test_r3_gap4_egress_guard_blocks_trailing_dot_and_sub_localhost(blocked_url: str) -> None:
    guard = EgressGuard()
    with pytest.raises(EgressBlockedError):
        guard.validate_url(blocked_url)
    # Also verify allow_loopback_for_tests=True allows localhost. and *.localhost
    permissive = EgressGuard(allow_loopback_for_tests=True)
    if blocked_url != "http://./":
        assert permissive.validate_url(blocked_url) == blocked_url
    else:
        with pytest.raises(EgressBlockedError):
            permissive.validate_url(blocked_url)


class _FakeMouse:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    async def click(self, x: float, y: float, *, button: str = "left") -> None:
        self.calls.append(("click", (x, y), {"button": button}))

    async def dblclick(self, x: float, y: float) -> None:
        self.calls.append(("dblclick", (x, y), {}))

    async def move(self, x: float, y: float) -> None:
        self.calls.append(("move", (x, y), {}))

    async def wheel(self, dx: float, dy: float) -> None:
        self.calls.append(("wheel", (dx, dy), {}))


class _FakeKeyboard:
    async def type(self, text: str) -> None:
        del text

    async def press(self, key: str) -> None:
        del key


class _FakePage:
    def __init__(self) -> None:
        self.mouse = _FakeMouse()
        self.keyboard = _FakeKeyboard()
        self.url = "https://example.com/"

    def is_closed(self) -> bool:
        return False


@pytest.mark.parametrize(
    "bad_value",
    [None, True, False, float("nan"), float("inf"), float("-inf"), "nan", "inf", "", "abc", []],
)
def test_r4_gap4_coerce_finite_float_rejects_invalid_values(bad_value: Any) -> None:
    from src.web.live_browser import _coerce_finite_float

    with pytest.raises(ValueError, match="finite number"):
        _coerce_finite_float(bad_value, field="x")


async def test_r4_gap4_live_browser_apply_input_rejects_null_bool_and_non_finite(
    tmp_path: Path,
) -> None:
    from src.web.live_browser import LiveBrowserController

    ctrl = LiveBrowserController(profile_root=tmp_path / "browser")
    fake_page = _FakePage()
    ctrl._context = object()  # type: ignore[assignment]
    ctrl._page = fake_page  # type: ignore[assignment]

    invalid_events: list[dict[str, Any]] = [
        {"type": "click", "x": None, "y": 10},
        {"type": "click", "x": 10, "y": None},
        {"type": "click", "x": True, "y": 10},
        {"type": "dblclick", "x": float("nan"), "y": 10},
        {"type": "move", "x": 10, "y": float("inf")},
        {"type": "wheel", "dx": float("inf"), "dy": 0},
        {"type": "wheel", "dx": 0, "dy": None},
        {"type": "wheel", "x": None, "dx": 0, "dy": 10},
        {"type": "scroll", "delta_x": False, "delta_y": 10},
        {"type": "scroll", "delta_x": 0, "delta_y": float("-inf")},
    ]
    for ev in invalid_events:
        with pytest.raises(ValueError, match="finite number"):
            await ctrl.handle_input(ev)

    assert fake_page.mouse.calls == []

    # Valid inputs pass through cleanly
    await ctrl.handle_input({"type": "click", "x": 120.5, "y": 240})
    await ctrl.handle_input({"type": "move", "x": 50, "y": 60})
    await ctrl.handle_input({"type": "wheel", "dx": -10, "dy": 120})
    await ctrl.handle_input({"type": "scroll", "delta_x": 0, "delta_y": -60})
    assert [c[0] for c in fake_page.mouse.calls] == ["click", "move", "wheel", "wheel"]


@pytest.mark.parametrize(
    "ssrf_url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/hook",
        "http://10.0.0.1/hook",
        "http://localhost./hook",
        "http://foo.localhost/hook",
        "http://printer.local/hook",
        "http://meta.internal/hook",
    ],
)
async def test_r4_gap3_deliver_draft_blocks_ssrf_with_zero_outbound_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssrf_url: str,
) -> None:
    import httpx
    from src.web.live_browser import LiveBrowserController
    from src.web.stub import InMemoryCoordinatorStub
    from src.web.v1.events import EventBus
    from src.web.v1.runner import AgentTurnRunner
    from src.web.v1.store import WorkspaceStore

    attempted_urls: list[str] = []

    class _SpyAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

        async def __aenter__(self) -> _SpyAsyncClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, **kwargs: Any) -> Any:
            del kwargs
            attempted_urls.append(url)
            raise AssertionError(f"Outbound request should not have been attempted for {url}")

    monkeypatch.setattr(httpx, "AsyncClient", _SpyAsyncClient)

    store = WorkspaceStore(tmp_path / "ws_ssrf.sqlite3")
    bus = EventBus()
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        draft = store.create_draft(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            channel_type="webhook",
            fields={"webhook_url": ssrf_url, "message": "ssrf probe"},
        )
        res = await runner.deliver_draft(draft)
        assert res["delivered"] is False
        assert res["transport"] == "webhook"
        assert "SSRF policy" in str(res.get("error") or "")
        assert attempted_urls == []
    finally:
        bus.close()
        store.close()
