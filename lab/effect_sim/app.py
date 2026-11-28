"""Synthetic Effect Simulator FastAPI app for idempotency and crash-reconciliation tests."""

from __future__ import annotations

import json
import os
import signal
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


class ApplyEffectRequest(BaseModel):
    """Payload accepted by POST /api/effects/apply."""

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str
    asset_id: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)
    fail_after_apply: bool | str = False


@dataclass
class EffectSimState:
    """Persistent or in-memory state for EffectSim."""

    state_path: Path | None = None
    total_applied: int = 0
    total_apply_requests: int = 0
    deduplicated_hits: int = 0
    effects: list[dict[str, Any]] = field(default_factory=list)
    by_key: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state_path is not None and self.state_path.exists():
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.total_applied = int(raw.get("total_applied", 0))
            self.total_apply_requests = int(raw.get("total_apply_requests", 0))
            self.deduplicated_hits = int(raw.get("deduplicated_hits", 0))
            self.effects = list(raw.get("effects", []))
            self.by_key = dict(raw.get("by_key", {}))

    def persist(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "total_applied": self.total_applied,
            "total_apply_requests": self.total_apply_requests,
            "deduplicated_hits": self.deduplicated_hits,
            "effects": self.effects,
            "by_key": self.by_key,
        }
        tmp_path = self.state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_path, self.state_path)


def create_effect_sim_app(
    *,
    state_path: Path | str | None = None,
    state: EffectSimState | None = None,
) -> FastAPI:
    """Create the synthetic EffectSim FastAPI app."""
    resolved_path = Path(state_path) if state_path is not None else None
    sim_state = state if state is not None else EffectSimState(state_path=resolved_path)

    app = FastAPI(title="Synthetic Effect Simulator", version="1.0.0")
    app.state.effect_sim_state = sim_state

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok",
                "available": True,
                "service": "effect_sim",
                "total_applied": sim_state.total_applied,
            },
        )

    @app.post("/api/effects/apply", response_model=None)
    async def apply_effect(payload: ApplyEffectRequest) -> JSONResponse:
        key = payload.idempotency_key.strip()
        asset_id = payload.asset_id.strip()
        action = payload.action.strip()
        if not key or not asset_id or not action:
            return JSONResponse(
                {
                    "detail": "idempotency_key, asset_id, and action must be non-empty.",
                    "code": "INVALID_INPUT",
                },
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            )

        sim_state.total_apply_requests += 1
        existing = sim_state.by_key.get(key)
        if existing is not None:
            if (
                existing["asset_id"] != asset_id
                or existing["action"] != action
                or existing["params"] != payload.params
            ):
                sim_state.persist()
                return JSONResponse(
                    {
                        "detail": (
                            f"Conflicting payload for idempotency_key={key!r}. "
                            "Retry with a new idempotency_key or match the original payload."
                        ),
                        "code": "IDEMPOTENCY_CONFLICT",
                    },
                    status_code=status.HTTP_409_CONFLICT,
                )
            sim_state.deduplicated_hits += 1
            sim_state.persist()
            return JSONResponse(
                {
                    **existing,
                    "deduplicated": True,
                    "total_applied": sim_state.total_applied,
                },
                status_code=status.HTTP_200_OK,
            )

        record = {
            "effect_id": f"eff-{uuid.uuid4().hex[:12]}",
            "idempotency_key": key,
            "asset_id": asset_id,
            "action": action,
            "params": payload.params,
            "applied_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        sim_state.total_applied += 1
        sim_state.effects.append(record)
        sim_state.by_key[key] = record
        sim_state.persist()

        if payload.fail_after_apply is True or payload.fail_after_apply == "http_500":
            return JSONResponse(
                {
                    "detail": "Simulated crash after persisting effect",
                    "code": "CRASH_AFTER_APPLY",
                },
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        if payload.fail_after_apply == "sigkill":
            os.kill(os.getpid(), signal.SIGKILL)

        return JSONResponse(
            {
                **record,
                "deduplicated": False,
                "total_applied": sim_state.total_applied,
            },
            status_code=status.HTTP_200_OK,
        )

    @app.get("/api/effects/state", response_model=None)
    async def get_state(idempotency_key: Annotated[str | None, Query()] = None) -> JSONResponse:
        body: dict[str, Any] = {
            "total_applied": sim_state.total_applied,
            "total_unique_effects": len(sim_state.by_key),
            "total_apply_requests": sim_state.total_apply_requests,
            "deduplicated_hits": sim_state.deduplicated_hits,
            "effects": sim_state.effects,
            "by_key": sim_state.by_key,
        }
        if idempotency_key is not None:
            match = sim_state.by_key.get(idempotency_key)
            body["found"] = match is not None
            body["effect"] = match
        return JSONResponse(body, status_code=status.HTTP_200_OK)

    @app.get("/api/effects/state/{idempotency_key}", response_model=None)
    async def get_state_by_key(idempotency_key: str) -> JSONResponse:
        match = sim_state.by_key.get(idempotency_key)
        if match is None:
            return JSONResponse(
                {"found": False, "effect": None},
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return JSONResponse(
            {"found": True, "effect": match},
            status_code=status.HTTP_200_OK,
        )

    return app
