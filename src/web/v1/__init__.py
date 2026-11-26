"""Grok Bot UX/UI `/api/v1` and `/ws/v1` FastAPI integration package."""

from __future__ import annotations

from src.web.v1.computer import ComputerGateway, create_computer_router
from src.web.v1.events import EventBus, scrub_v1_payload
from src.web.v1.rfb_gate import RfbInputGate, decrypt_vnc_passwd_file, solve_vnc_challenge
from src.web.v1.routes import create_v1_router
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import WorkspaceStore

__all__ = [
    "AgentTurnRunner",
    "ComputerGateway",
    "EventBus",
    "RfbInputGate",
    "WorkspaceStore",
    "create_computer_router",
    "create_v1_router",
    "decrypt_vnc_passwd_file",
    "scrub_v1_payload",
    "solve_vnc_challenge",
]
