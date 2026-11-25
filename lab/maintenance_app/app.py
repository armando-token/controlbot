"""Synthetic Maintenance FastAPI web application for N2/E2E testing."""

from __future__ import annotations

import html
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import parse_qs

from fastapi import Cookie, FastAPI, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

VALID_MAINTENANCE_MODES: frozenset[str] = frozenset(
    {
        "default",
        "ambiguity",
        "ambiguous",
        "stale",
        "bad_quality",
        "out_of_window",
        "auth_expired",
        "down",
        "contradictory",
        "reordered",
        "facility_b",
        "area2",
    }
)

DEFAULT_MAINT_COLUMNS: tuple[str, ...] = (
    "id",
    "asset_id",
    "asset_label",
    "intervention",
    "recorded_at",
    "area",
    "quality",
)

REORDERED_MAINT_COLUMNS: tuple[str, ...] = (
    "recorded_at",
    "quality",
    "intervention",
    "asset_label",
    "asset_id",
    "area",
    "id",
)

_HEADER_LABELS: dict[str, str] = {
    "id": "ID",
    "asset_id": "Asset ID",
    "asset_label": "Asset",
    "intervention": "Intervention",
    "recorded_at": "Recorded At",
    "area": "Area",
    "quality": "Quality",
}

FACILITY_B_MAINT_HEADER_LABELS: dict[str, str] = {
    "id": "Orden",
    "asset_id": "Código CMMS",
    "asset_label": "Equipo",
    "intervention": "Intervención",
    "recorded_at": "Hora de registro",
    "area": "Área",
    "quality": "Calidad",
}

FACILITY_B_WORK_ORDERS_TABLE_LABEL = "Órdenes de Mantenimiento Planta B"


@dataclass(frozen=True)
class MaintenanceUser:
    """Synthetic Maintenance account."""

    username: str
    password: str
    areas: tuple[str, ...]
    role: str


DEFAULT_MAINT_USERS: dict[str, MaintenanceUser] = {
    "maint_a": MaintenanceUser("maint_a", "maint-pass-a", ("area-1",), "technician"),
    "maint_a1": MaintenanceUser("maint_a1", "maint-pass-a1", ("area-1",), "technician"),
    "maint_b": MaintenanceUser("maint_b", "maint-pass-b", ("area-2",), "technician"),
    "maint_a2": MaintenanceUser("maint_a2", "maint-pass-a2", ("area-2",), "technician"),
    "maint_ro": MaintenanceUser("maint_ro", "maint-pass-ro", ("area-1", "area-2"), "auditor"),
}


@dataclass
class MaintenanceSessionRecord:
    """In-memory Maintenance cookie session."""

    token: str
    username: str
    areas: tuple[str, ...]
    role: str
    expired: bool = False


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class MaintenanceState:
    """Mutable test-controlled state for the synthetic Maintenance server."""

    fixture_mode: str = "default"
    column_order: tuple[str, ...] = DEFAULT_MAINT_COLUMNS
    reference_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    users: dict[str, MaintenanceUser] = field(default_factory=lambda: dict(DEFAULT_MAINT_USERS))
    sessions: dict[str, MaintenanceSessionRecord] = field(default_factory=dict)
    header_labels: dict[str, str] = field(default_factory=lambda: dict(_HEADER_LABELS))
    work_orders_table_label: str = "Maintenance Work Orders"
    custom_work_orders: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.fixture_mode not in VALID_MAINTENANCE_MODES:
            raise ValueError(f"Unsupported Maintenance fixture_mode: {self.fixture_mode!r}")

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MAINTENANCE_MODES:
            raise ValueError(f"Unsupported Maintenance fixture_mode: {mode!r}")
        self.fixture_mode = mode
        if mode == "reordered":
            self.column_order = REORDERED_MAINT_COLUMNS
        elif mode in ("facility_b", "area2"):
            self.column_order = REORDERED_MAINT_COLUMNS
            self.header_labels = dict(FACILITY_B_MAINT_HEADER_LABELS)
            self.work_orders_table_label = FACILITY_B_WORK_ORDERS_TABLE_LABEL

    def set_column_order(self, order: tuple[str, ...]) -> None:
        self.column_order = order

    def set_reference_time(self, dt: datetime) -> None:
        if dt.tzinfo is None:
            raise ValueError("reference_time must be timezone-aware")
        self.reference_time = dt.astimezone(UTC)

    def expire_all_sessions(self) -> None:
        for sess in self.sessions.values():
            sess.expired = True

    def expire_session(self, token: str) -> None:
        if token in self.sessions:
            self.sessions[token].expired = True

    def get_work_orders(self) -> list[dict[str, Any]]:
        if self.custom_work_orders is not None:
            return [dict(row) for row in self.custom_work_orders]
        ref = self.reference_time
        mode = self.fixture_mode
        if mode in ("facility_b", "area2"):
            asset_code = "bomba-77-b2" if mode == "area2" else "CMMS-77"
            return [
                {
                    "id": "WO-7701",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "intervention": "Inspected east cooling impeller and bearing housing",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=55)),
                    "area": "area-2",
                    "quality": "good",
                },
                {
                    "id": "WO-7705",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "intervention": "Replaced mechanical seal and calibrated pressure transmitter",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=10)),
                    "area": "area-2",
                    "quality": "good",
                },
            ]
        if mode in ("ambiguity", "ambiguous"):
            return [
                {
                    "id": "WO-3408",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "intervention": "Replaced mechanical seal and realigned shaft coupling",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=12)),
                    "area": "area-1",
                    "quality": "good",
                },
                {
                    "id": "WO-3409",
                    "asset_id": "bomba-34-a2",
                    "asset_label": "bomba 34",
                    "intervention": "Cleaned intake strainer and pressure gauge",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=10)),
                    "area": "area-2",
                    "quality": "good",
                },
            ]
        if mode == "contradictory":
            return [
                {
                    "id": "WO-3498",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 35",
                    "intervention": "Shaft alignment on Bomba 35 (labeled bomba-34-a1)",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=20)),
                    "area": "area-1",
                    "quality": "good",
                },
                {
                    "id": "WO-3499",
                    "asset_id": "bomba-99-a1",
                    "asset_label": "bomba 34",
                    "intervention": (
                        "Replaced impeller on bomba 34 under conflicting ID bomba-99-a1"
                    ),
                    "recorded_at": _iso_utc(ref - timedelta(minutes=12)),
                    "area": "area-1",
                    "quality": "good",
                },
            ]
        if mode in ("stale", "bad_quality", "out_of_window"):
            return [
                {
                    "id": "WO-OLD-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "intervention": "Legacy motor overhaul",
                    "recorded_at": _iso_utc(ref - timedelta(hours=4)),
                    "area": "area-1",
                    "quality": "good",
                },
                {
                    "id": "WO-BAD-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "intervention": "Unverified draft repair log",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=8)),
                    "area": "area-1",
                    "quality": "bad",
                },
                {
                    "id": "WO-3410",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "intervention": "Verified vibration sensor recalibration",
                    "recorded_at": _iso_utc(ref - timedelta(minutes=15)),
                    "area": "area-1",
                    "quality": "good",
                },
            ]
        return [
            {
                "id": "WO-3401",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "intervention": "Bearing lubrication inspection",
                "recorded_at": _iso_utc(ref - timedelta(minutes=50)),
                "area": "area-1",
                "quality": "good",
            },
            {
                "id": "WO-3408",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "intervention": "Replaced mechanical seal and realigned shaft coupling",
                "recorded_at": _iso_utc(ref - timedelta(minutes=12)),
                "area": "area-1",
                "quality": "good",
            },
        ]


def _filter_work_orders(
    records: list[dict[str, Any]],
    allowed_areas: tuple[str, ...],
    asset_id: str | None,
    asset: str | None,
    area: str | None,
    *,
    mode: str = "default",
) -> tuple[list[dict[str, Any]], bool]:
    if area is not None and area not in allowed_areas:
        return [], False
    area2_aliases = {"CMMS-77", "bomba-77-b2"}
    result: list[dict[str, Any]] = []
    for row in records:
        if row["area"] not in allowed_areas:
            continue
        if area is not None and row["area"] != area:
            continue
        if asset_id is not None:
            if mode == "area2" and asset_id in area2_aliases:
                if row["asset_id"] not in area2_aliases:
                    continue
            elif row["asset_id"] != asset_id:
                continue
        if asset is not None and asset.strip().lower() not in (
            str(row["asset_label"]).lower(),
            str(row["asset_id"]).lower(),
        ):
            continue
        result.append(row)
    return result, True


def _render_work_orders_html(
    *,
    username: str,
    areas: tuple[str, ...],
    rows: list[dict[str, Any]],
    column_order: tuple[str, ...],
    table_label: str = "Maintenance Work Orders",
    header_labels: Mapping[str, str] | None = None,
) -> str:
    labels_map = header_labels if header_labels is not None else _HEADER_LABELS
    headers_html = "".join(
        f"<th scope=\"col\">{html.escape(labels_map.get(col, col))}</th>"
        for col in column_order
    )
    body_rows: list[str] = []
    for row in rows:
        cells = "".join(
            f"<td data-col=\"{html.escape(col)}\">{html.escape(str(row.get(col, '')))}</td>"
            for col in column_order
        )
        body_rows.append(
            f"<tr data-record-id=\"{html.escape(str(row['id']))}\" "
            f"data-asset-id=\"{html.escape(str(row['asset_id']))}\" "
            f"data-area=\"{html.escape(str(row['area']))}\" "
            f"data-quality=\"{html.escape(str(row['quality']))}\">{cells}</tr>"
        )
    user_json = json.dumps(username)
    areas_json = json.dumps(list(areas))
    escaped_label = html.escape(table_label)
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{escaped_label}</title></head><body>"
        "<main>"
        f"<h1 data-testid=\"page-title\">{escaped_label}</h1>"
        f"<div data-testid=\"current-user\">{html.escape(username)}</div>"
        f"<div data-testid=\"user-areas\">{html.escape(','.join(areas))}</div>"
        f"<table aria-label=\"{escaped_label}\">"
        f"<thead><tr>{headers_html}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "<form method=\"post\" action=\"/logout\">"
        "<button type=\"submit\">Sign Out</button>"
        "</form>"
        "</main>"
        "<script>"
        f"window.localStorage.setItem('maint_user', {user_json});"
        f"window.localStorage.setItem('maint_areas', JSON.stringify({areas_json}));"
        "</script>"
        "</body></html>"
    )


def create_maintenance_app(
    fixture_mode: str = "default",
    *,
    state: MaintenanceState | None = None,
    column_order: tuple[str, ...] | None = None,
    header_labels: Mapping[str, str] | None = None,
    work_orders_table_label: str | None = None,
    custom_work_orders: list[dict[str, Any]] | None = None,
    users: Mapping[str, MaintenanceUser] | None = None,
) -> FastAPI:
    """Create an independent synthetic Maintenance web application."""
    if state is None:
        effective_cols = column_order or (
            REORDERED_MAINT_COLUMNS
            if fixture_mode in ("reordered", "facility_b", "area2")
            else DEFAULT_MAINT_COLUMNS
        )
        effective_headers = (
            dict(header_labels)
            if header_labels is not None
            else (
                dict(FACILITY_B_MAINT_HEADER_LABELS)
                if fixture_mode in ("facility_b", "area2")
                else dict(_HEADER_LABELS)
            )
        )
        effective_table_label = (
            work_orders_table_label
            if work_orders_table_label is not None
            else (
                FACILITY_B_WORK_ORDERS_TABLE_LABEL
                if fixture_mode in ("facility_b", "area2")
                else "Maintenance Work Orders"
            )
        )
        maint_state = MaintenanceState(
            fixture_mode=fixture_mode,
            column_order=effective_cols,
            users=dict(users) if users is not None else dict(DEFAULT_MAINT_USERS),
            header_labels=effective_headers,
            work_orders_table_label=effective_table_label,
            custom_work_orders=(
                [dict(r) for r in custom_work_orders] if custom_work_orders is not None else None
            ),
        )
    else:
        maint_state = state
        if column_order is not None:
            maint_state.set_column_order(column_order)
        if header_labels is not None:
            maint_state.header_labels = dict(header_labels)
        if work_orders_table_label is not None:
            maint_state.work_orders_table_label = work_orders_table_label
        if custom_work_orders is not None:
            maint_state.custom_work_orders = [dict(r) for r in custom_work_orders]
        if users is not None:
            maint_state.users = dict(users)

    app = FastAPI(title="Synthetic Maintenance Lab", version="1.0.0")
    app.state.maintenance_state = maint_state

    def _authenticate(token: str | None) -> MaintenanceSessionRecord | None:
        if maint_state.fixture_mode == "auth_expired":
            return None
        if not token:
            return None
        sess = maint_state.sessions.get(token)
        if sess is None or sess.expired:
            return None
        return sess

    @app.get("/health")
    async def health() -> JSONResponse:
        available = maint_state.fixture_mode != "down"
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok" if available else "degraded",
                "available": available,
                "service": "maintenance",
                "fixture_mode": maint_state.fixture_mode,
            },
        )

    @app.get("/login", response_model=None)
    async def login_page(expired: int = 0) -> Response:
        if maint_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 Maintenance Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        banner = (
            "<p role=\"alert\" data-testid=\"auth-expired-banner\">"
            "Session expired. Please sign in again.</p>"
            if expired or maint_state.fixture_mode == "auth_expired"
            else ""
        )
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Maintenance Login</title></head><body><main>"
            "<h1>Maintenance Login</h1>"
            f"{banner}"
            "<form method=\"post\" action=\"/login\">"
            "<label for=\"username\">Username</label>"
            "<input id=\"username\" name=\"username\" type=\"text\" required>"
            "<label for=\"password\">Password</label>"
            "<input id=\"password\" name=\"password\" type=\"password\" required>"
            "<button type=\"submit\">Sign In</button>"
            "</form></main></body></html>"
        )
        return HTMLResponse(body, status_code=status.HTTP_200_OK)

    @app.post("/login", response_model=None)
    async def login_submit(request: Request) -> Response:
        if maint_state.fixture_mode == "down":
            return JSONResponse(
                {"detail": "Maintenance service unavailable", "code": "SERVICE_DOWN"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        content_type = request.headers.get("content-type", "").lower()
        is_json = "application/json" in content_type
        username = ""
        password = ""
        if is_json:
            payload = await request.json()
            if isinstance(payload, dict):
                username = str(payload.get("username", ""))
                password = str(payload.get("password", ""))
        else:
            raw_body = (await request.body()).decode("utf-8")
            parsed_form = parse_qs(raw_body, keep_blank_values=True)
            username = parsed_form.get("username", [""])[0]
            password = parsed_form.get("password", [""])[0]

        user = maint_state.users.get(username)
        if user is None or user.password != password:
            if is_json:
                return JSONResponse(
                    {"detail": "Invalid credentials", "code": "INVALID_CREDENTIALS"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            return HTMLResponse(
                "<h1>Invalid credentials</h1><a href=\"/login\">Retry</a>",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        token = secrets.token_urlsafe(24)
        maint_state.sessions[token] = MaintenanceSessionRecord(
            token=token,
            username=user.username,
            areas=user.areas,
            role=user.role,
            expired=maint_state.fixture_mode == "auth_expired",
        )
        if is_json:
            resp: Response = JSONResponse(
                {
                    "status": "authenticated",
                    "user": user.username,
                    "areas": list(user.areas),
                },
                status_code=status.HTTP_200_OK,
            )
        else:
            resp = RedirectResponse(url="/work-orders", status_code=status.HTTP_303_SEE_OTHER)
        resp.set_cookie(
            key="maint_session",
            value=token,
            max_age=3600,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return resp

    @app.post("/logout", response_model=None)
    async def logout(
        request: Request,
        maint_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        if maint_session and maint_session in maint_state.sessions:
            del maint_state.sessions[maint_session]
        is_json = "application/json" in request.headers.get("accept", "").lower()
        resp: Response = (
            JSONResponse({"status": "logged_out"}, status_code=status.HTTP_200_OK)
            if is_json
            else RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        )
        resp.delete_cookie("maint_session", path="/")
        return resp

    @app.get("/", response_model=None)
    async def root(maint_session: Annotated[str | None, Cookie()] = None) -> Response:
        if maint_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 Maintenance Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if _authenticate(maint_session) is None:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/work-orders", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/work-orders", response_model=None)
    async def work_orders_html(
        maint_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> Response:
        if maint_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 Maintenance Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(maint_session)
        if sess is None:
            login_url = (
                "/login?expired=1"
                if (maint_session is not None or maint_state.fixture_mode == "auth_expired")
                else "/login"
            )
            return RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)
        rows, allowed = _filter_work_orders(
            maint_state.get_work_orders(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=maint_state.fixture_mode,
        )
        if not allowed:
            return HTMLResponse(
                "<h1>403 Forbidden Area</h1>",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        page_html = _render_work_orders_html(
            username=sess.username,
            areas=sess.areas,
            rows=rows,
            column_order=maint_state.column_order,
            table_label=maint_state.work_orders_table_label,
            header_labels=maint_state.header_labels,
        )
        return HTMLResponse(page_html, status_code=status.HTTP_200_OK)

    @app.get("/api/work_orders", response_model=None)
    async def api_work_orders(
        maint_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> JSONResponse:
        if maint_state.fixture_mode == "down":
            return JSONResponse(
                {"detail": "Maintenance service unavailable", "code": "SERVICE_DOWN"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(maint_session)
        if sess is None:
            return JSONResponse(
                {"detail": "Session expired", "code": "AUTH_EXPIRED"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        rows, allowed = _filter_work_orders(
            maint_state.get_work_orders(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=maint_state.fixture_mode,
        )
        if not allowed:
            return JSONResponse(
                {"detail": "Forbidden area", "code": "FORBIDDEN_AREA"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return JSONResponse(
            {"source": "maintenance", "user": sess.username, "work_orders": rows},
            status_code=status.HTTP_200_OK,
        )

    return app
