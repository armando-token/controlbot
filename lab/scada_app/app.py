"""Synthetic SCADA FastAPI web application for N2/E2E testing."""

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

VALID_SCADA_MODES: frozenset[str] = frozenset(
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

DEFAULT_SCADA_COLUMNS: tuple[str, ...] = (
    "id",
    "asset_id",
    "asset_label",
    "value",
    "unit",
    "time",
    "quality",
    "area",
)

REORDERED_SCADA_COLUMNS: tuple[str, ...] = (
    "time",
    "quality",
    "value",
    "unit",
    "asset_label",
    "asset_id",
    "area",
    "id",
)

_HEADER_LABELS: dict[str, str] = {
    "id": "ID",
    "asset_id": "Asset ID",
    "asset_label": "Asset",
    "value": "Value",
    "unit": "Unit",
    "time": "Time",
    "quality": "Quality",
    "area": "Area",
}

FACILITY_B_SCADA_HEADER_LABELS: dict[str, str] = {
    "id": "Registro",
    "asset_id": "Tag SCADA",
    "asset_label": "Equipo",
    "value": "Valor",
    "unit": "Unidad",
    "time": "Hora",
    "quality": "Calidad",
    "area": "Área",
}

FACILITY_B_ALARMS_TABLE_LABEL = "Alarmas SCADA Planta B"
FACILITY_B_READINGS_TABLE_LABEL = "Lecturas SCADA Planta B"


@dataclass(frozen=True)
class ScadaUser:
    """Synthetic SCADA operator account."""

    username: str
    password: str
    areas: tuple[str, ...]
    role: str


DEFAULT_SCADA_USERS: dict[str, ScadaUser] = {
    "operator_a": ScadaUser("operator_a", "scada-pass-a", ("area-1",), "operator"),
    "operator_a1": ScadaUser("operator_a1", "scada-pass-a1", ("area-1",), "operator"),
    "operator_b": ScadaUser("operator_b", "scada-pass-b", ("area-2",), "operator"),
    "operator_a2": ScadaUser("operator_a2", "scada-pass-a2", ("area-2",), "operator"),
    "operator_ro": ScadaUser("operator_ro", "scada-pass-ro", ("area-1", "area-2"), "auditor"),
}


@dataclass
class ScadaSessionRecord:
    """In-memory SCADA cookie session."""

    token: str
    username: str
    areas: tuple[str, ...]
    role: str
    expired: bool = False


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ScadaState:
    """Mutable test-controlled state for the synthetic SCADA server."""

    fixture_mode: str = "default"
    column_order: tuple[str, ...] = DEFAULT_SCADA_COLUMNS
    reference_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    users: dict[str, ScadaUser] = field(default_factory=lambda: dict(DEFAULT_SCADA_USERS))
    sessions: dict[str, ScadaSessionRecord] = field(default_factory=dict)
    header_labels: dict[str, str] = field(default_factory=lambda: dict(_HEADER_LABELS))
    alarms_table_label: str = "SCADA Alarms"
    readings_table_label: str = "SCADA Readings"
    custom_alarms: list[dict[str, Any]] | None = None
    custom_readings: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.fixture_mode not in VALID_SCADA_MODES:
            raise ValueError(f"Unsupported SCADA fixture_mode: {self.fixture_mode!r}")

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_SCADA_MODES:
            raise ValueError(f"Unsupported SCADA fixture_mode: {mode!r}")
        self.fixture_mode = mode
        if mode == "reordered":
            self.column_order = REORDERED_SCADA_COLUMNS
        elif mode in ("facility_b", "area2"):
            self.column_order = REORDERED_SCADA_COLUMNS
            self.header_labels = dict(FACILITY_B_SCADA_HEADER_LABELS)
            self.alarms_table_label = FACILITY_B_ALARMS_TABLE_LABEL
            self.readings_table_label = FACILITY_B_READINGS_TABLE_LABEL

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

    def get_alarms(self) -> list[dict[str, Any]]:
        if self.custom_alarms is not None:
            return [dict(row) for row in self.custom_alarms]
        ref = self.reference_time
        mode = self.fixture_mode
        if mode in ("facility_b", "area2"):
            asset_code = "bomba-77-b2" if mode == "area2" else "SC-77"
            return [
                {
                    "id": "ALM-7701",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "value": "SEAL_TEMP_HIGH",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(minutes=40)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "warning",
                },
                {
                    "id": "ALM-7702",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "value": "PRESSURE_DROP",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(minutes=15)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "warning",
                },
            ]
        if mode in ("ambiguity", "ambiguous"):
            return [
                {
                    "id": "ALM-3401",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": "HIGH_VIBRATION",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(minutes=30)),
                    "quality": "good",
                    "area": "area-1",
                    "severity": "warning",
                },
                {
                    "id": "ALM-3409",
                    "asset_id": "bomba-34-a2",
                    "asset_label": "bomba 34",
                    "value": "SEAL_LEAK",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(minutes=25)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "critical",
                },
            ]
        if mode in ("stale", "bad_quality", "out_of_window"):
            return [
                {
                    "id": "ALM-OLD-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": "HISTORICAL_TRIP",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(hours=3)),
                    "quality": "good",
                    "area": "area-1",
                    "severity": "warning",
                },
                {
                    "id": "ALM-3405",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": "CAVITATION_WARNING",
                    "unit": "alarm_code",
                    "time": _iso_utc(ref - timedelta(minutes=25)),
                    "quality": "good",
                    "area": "area-1",
                    "severity": "warning",
                },
            ]
        return [
            {
                "id": "ALM-3401",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "value": "HIGH_VIBRATION",
                "unit": "alarm_code",
                "time": _iso_utc(ref - timedelta(minutes=35)),
                "quality": "good",
                "area": "area-1",
                "severity": "warning",
            },
            {
                "id": "ALM-3402",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "value": "TEMP_SPIKE",
                "unit": "alarm_code",
                "time": _iso_utc(ref - timedelta(minutes=15)),
                "quality": "good",
                "area": "area-1",
                "severity": "warning",
            },
        ]

    def get_readings(self) -> list[dict[str, Any]]:
        if self.custom_readings is not None:
            return [dict(row) for row in self.custom_readings]
        ref = self.reference_time
        mode = self.fixture_mode
        if mode in ("facility_b", "area2"):
            asset_code = "bomba-77-b2" if mode == "area2" else "SC-77"
            return [
                {
                    "id": "RDG-7701",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "value": 6.8,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=12)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "info",
                },
                {
                    "id": "RDG-7702",
                    "asset_id": asset_code,
                    "asset_label": "bomba 77",
                    "value": 5.1,
                    "unit": "bar",
                    "time": _iso_utc(ref - timedelta(minutes=4)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "info",
                },
            ]
        if mode in ("ambiguity", "ambiguous"):
            return [
                {
                    "id": "RDG-3401",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": 8.1,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=10)),
                    "quality": "good",
                    "area": "area-1",
                    "severity": "info",
                },
                {
                    "id": "RDG-3409",
                    "asset_id": "bomba-34-a2",
                    "asset_label": "bomba 34",
                    "value": 9.7,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=8)),
                    "quality": "good",
                    "area": "area-2",
                    "severity": "info",
                },
            ]
        if mode in ("stale", "bad_quality", "out_of_window"):
            return [
                {
                    "id": "RDG-STALE-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": 6.2,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=90)),
                    "quality": "stale",
                    "area": "area-1",
                    "severity": "info",
                },
                {
                    "id": "RDG-BAD-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": 999.9,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=5)),
                    "quality": "bad",
                    "area": "area-1",
                    "severity": "error",
                },
                {
                    "id": "RDG-GOOD-01",
                    "asset_id": "bomba-34-a1",
                    "asset_label": "bomba 34",
                    "value": 7.5,
                    "unit": "mm/s",
                    "time": _iso_utc(ref - timedelta(minutes=4)),
                    "quality": "good",
                    "area": "area-1",
                    "severity": "info",
                },
            ]
        return [
            {
                "id": "RDG-3401",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "value": 8.4,
                "unit": "mm/s",
                "time": _iso_utc(ref - timedelta(minutes=10)),
                "quality": "good",
                "area": "area-1",
                "severity": "info",
            },
            {
                "id": "RDG-3402",
                "asset_id": "bomba-34-a1",
                "asset_label": "bomba 34",
                "value": 4.2,
                "unit": "bar",
                "time": _iso_utc(ref - timedelta(minutes=5)),
                "quality": "good",
                "area": "area-1",
                "severity": "info",
            },
        ]


def _filter_records(
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
    area2_aliases = {"SC-77", "bomba-77-b2"}
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


def _render_table_html(
    *,
    title: str,
    table_label: str,
    username: str,
    areas: tuple[str, ...],
    rows: list[dict[str, Any]],
    column_order: tuple[str, ...],
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
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title></head><body>"
        "<main>"
        f"<h1 data-testid=\"page-title\">{html.escape(title)}</h1>"
        f"<div data-testid=\"current-user\">{html.escape(username)}</div>"
        f"<div data-testid=\"user-areas\">{html.escape(','.join(areas))}</div>"
        f"<table aria-label=\"{html.escape(table_label)}\">"
        f"<thead><tr>{headers_html}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "<form method=\"post\" action=\"/logout\">"
        "<button type=\"submit\">Sign Out</button>"
        "</form>"
        "</main>"
        "<script>"
        f"window.localStorage.setItem('scada_user', {user_json});"
        f"window.localStorage.setItem('scada_areas', JSON.stringify({areas_json}));"
        "</script>"
        "</body></html>"
    )


def create_scada_app(
    fixture_mode: str = "default",
    *,
    state: ScadaState | None = None,
    column_order: tuple[str, ...] | None = None,
    header_labels: Mapping[str, str] | None = None,
    alarms_table_label: str | None = None,
    readings_table_label: str | None = None,
    custom_alarms: list[dict[str, Any]] | None = None,
    custom_readings: list[dict[str, Any]] | None = None,
    users: Mapping[str, ScadaUser] | None = None,
) -> FastAPI:
    """Create an independent synthetic SCADA web application."""
    if state is None:
        effective_cols = column_order or (
            REORDERED_SCADA_COLUMNS
            if fixture_mode in ("reordered", "facility_b", "area2")
            else DEFAULT_SCADA_COLUMNS
        )
        effective_headers = (
            dict(header_labels)
            if header_labels is not None
            else (
                dict(FACILITY_B_SCADA_HEADER_LABELS)
                if fixture_mode in ("facility_b", "area2")
                else dict(_HEADER_LABELS)
            )
        )
        effective_alarms_label = (
            alarms_table_label
            if alarms_table_label is not None
            else (
                FACILITY_B_ALARMS_TABLE_LABEL
                if fixture_mode in ("facility_b", "area2")
                else "SCADA Alarms"
            )
        )
        effective_readings_label = (
            readings_table_label
            if readings_table_label is not None
            else (
                FACILITY_B_READINGS_TABLE_LABEL
                if fixture_mode in ("facility_b", "area2")
                else "SCADA Readings"
            )
        )
        scada_state = ScadaState(
            fixture_mode=fixture_mode,
            column_order=effective_cols,
            users=dict(users) if users is not None else dict(DEFAULT_SCADA_USERS),
            header_labels=effective_headers,
            alarms_table_label=effective_alarms_label,
            readings_table_label=effective_readings_label,
            custom_alarms=[dict(r) for r in custom_alarms] if custom_alarms is not None else None,
            custom_readings=(
                [dict(r) for r in custom_readings] if custom_readings is not None else None
            ),
        )
    else:
        scada_state = state
        if column_order is not None:
            scada_state.set_column_order(column_order)
        if header_labels is not None:
            scada_state.header_labels = dict(header_labels)
        if alarms_table_label is not None:
            scada_state.alarms_table_label = alarms_table_label
        if readings_table_label is not None:
            scada_state.readings_table_label = readings_table_label
        if custom_alarms is not None:
            scada_state.custom_alarms = [dict(r) for r in custom_alarms]
        if custom_readings is not None:
            scada_state.custom_readings = [dict(r) for r in custom_readings]
        if users is not None:
            scada_state.users = dict(users)

    app = FastAPI(title="Synthetic SCADA Lab", version="1.0.0")
    app.state.scada_state = scada_state

    def _authenticate(token: str | None) -> ScadaSessionRecord | None:
        if scada_state.fixture_mode == "auth_expired":
            return None
        if not token:
            return None
        sess = scada_state.sessions.get(token)
        if sess is None or sess.expired:
            return None
        return sess

    @app.get("/health")
    async def health() -> JSONResponse:
        available = scada_state.fixture_mode != "down"
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok" if available else "degraded",
                "available": available,
                "service": "scada",
                "fixture_mode": scada_state.fixture_mode,
            },
        )

    @app.get("/login", response_model=None)
    async def login_page(expired: int = 0) -> Response:
        if scada_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 SCADA Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        banner = (
            "<p role=\"alert\" data-testid=\"auth-expired-banner\">"
            "Session expired. Please sign in again.</p>"
            if expired or scada_state.fixture_mode == "auth_expired"
            else ""
        )
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>SCADA Login</title></head><body><main>"
            "<h1>SCADA Login</h1>"
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
        if scada_state.fixture_mode == "down":
            return JSONResponse(
                {"detail": "SCADA service unavailable", "code": "SERVICE_DOWN"},
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

        user = scada_state.users.get(username)
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
        scada_state.sessions[token] = ScadaSessionRecord(
            token=token,
            username=user.username,
            areas=user.areas,
            role=user.role,
            expired=scada_state.fixture_mode == "auth_expired",
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
            resp = RedirectResponse(url="/alarms", status_code=status.HTTP_303_SEE_OTHER)
        resp.set_cookie(
            key="scada_session",
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
        scada_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        if scada_session and scada_session in scada_state.sessions:
            del scada_state.sessions[scada_session]
        is_json = "application/json" in request.headers.get("accept", "").lower()
        resp: Response = (
            JSONResponse({"status": "logged_out"}, status_code=status.HTTP_200_OK)
            if is_json
            else RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        )
        resp.delete_cookie("scada_session", path="/")
        return resp

    @app.get("/", response_model=None)
    async def root(scada_session: Annotated[str | None, Cookie()] = None) -> Response:
        if scada_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 SCADA Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if _authenticate(scada_session) is None:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/alarms", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/alarms", response_model=None)
    async def alarms_html(
        scada_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> Response:
        if scada_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 SCADA Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(scada_session)
        if sess is None:
            sess_record = scada_state.sessions.get(scada_session) if scada_session else None
            is_expired = scada_state.fixture_mode == "auth_expired" or (
                sess_record is not None and sess_record.expired
            )
            login_url = "/login?expired=1" if is_expired else "/login"
            resp = RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)
            if scada_session is not None and sess_record is None:
                resp.delete_cookie("scada_session", path="/")
            return resp
        rows, allowed = _filter_records(
            scada_state.get_alarms(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=scada_state.fixture_mode,
        )
        if not allowed:
            return HTMLResponse(
                "<h1>403 Forbidden Area</h1>",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        page_html = _render_table_html(
            title=scada_state.alarms_table_label,
            table_label=scada_state.alarms_table_label,
            username=sess.username,
            areas=sess.areas,
            rows=rows,
            column_order=scada_state.column_order,
            header_labels=scada_state.header_labels,
        )
        return HTMLResponse(page_html, status_code=status.HTTP_200_OK)

    @app.get("/readings", response_model=None)
    async def readings_html(
        scada_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> Response:
        if scada_state.fixture_mode == "down":
            return HTMLResponse(
                "<h1>503 SCADA Service Unavailable</h1>",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(scada_session)
        if sess is None:
            sess_record = scada_state.sessions.get(scada_session) if scada_session else None
            is_expired = scada_state.fixture_mode == "auth_expired" or (
                sess_record is not None and sess_record.expired
            )
            login_url = "/login?expired=1" if is_expired else "/login"
            resp = RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)
            if scada_session is not None and sess_record is None:
                resp.delete_cookie("scada_session", path="/")
            return resp
        rows, allowed = _filter_records(
            scada_state.get_readings(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=scada_state.fixture_mode,
        )
        if not allowed:
            return HTMLResponse(
                "<h1>403 Forbidden Area</h1>",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        page_html = _render_table_html(
            title=scada_state.readings_table_label,
            table_label=scada_state.readings_table_label,
            username=sess.username,
            areas=sess.areas,
            rows=rows,
            column_order=scada_state.column_order,
            header_labels=scada_state.header_labels,
        )
        return HTMLResponse(page_html, status_code=status.HTTP_200_OK)

    @app.get("/api/alarms", response_model=None)
    async def api_alarms(
        scada_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> JSONResponse:
        if scada_state.fixture_mode == "down":
            return JSONResponse(
                {"detail": "SCADA service unavailable", "code": "SERVICE_DOWN"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(scada_session)
        if sess is None:
            return JSONResponse(
                {"detail": "Session expired", "code": "AUTH_EXPIRED"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        rows, allowed = _filter_records(
            scada_state.get_alarms(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=scada_state.fixture_mode,
        )
        if not allowed:
            return JSONResponse(
                {"detail": "Forbidden area", "code": "FORBIDDEN_AREA"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return JSONResponse(
            {"source": "scada", "user": sess.username, "alarms": rows},
            status_code=status.HTTP_200_OK,
        )

    @app.get("/api/readings", response_model=None)
    async def api_readings(
        scada_session: Annotated[str | None, Cookie()] = None,
        asset_id: Annotated[str | None, Query()] = None,
        asset: Annotated[str | None, Query()] = None,
        area: Annotated[str | None, Query()] = None,
    ) -> JSONResponse:
        if scada_state.fixture_mode == "down":
            return JSONResponse(
                {"detail": "SCADA service unavailable", "code": "SERVICE_DOWN"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        sess = _authenticate(scada_session)
        if sess is None:
            return JSONResponse(
                {"detail": "Session expired", "code": "AUTH_EXPIRED"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        rows, allowed = _filter_records(
            scada_state.get_readings(),
            sess.areas,
            asset_id,
            asset,
            area,
            mode=scada_state.fixture_mode,
        )
        if not allowed:
            return JSONResponse(
                {"detail": "Forbidden area", "code": "FORBIDDEN_AREA"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return JSONResponse(
            {"source": "scada", "user": sess.username, "readings": rows},
            status_code=status.HTTP_200_OK,
        )

    return app
