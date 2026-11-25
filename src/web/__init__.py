"""Local FastAPI observability API and minimal HTML UI."""

from src.web.app import create_app
from src.web.protocols import (
    CoordinatorProtocol,
    SessionManagerProtocol,
    TaskSnapshot,
    TransitionRecord,
    maybe_await,
)
from src.web.schemas import (
    CancelRequest,
    ReleaseRequest,
    ResumeRequest,
    TakeoverRequest,
    TaskSubmitRequest,
)
from src.web.stub import InMemoryCoordinatorStub

__all__ = [
    "CancelRequest",
    "CoordinatorProtocol",
    "InMemoryCoordinatorStub",
    "ReleaseRequest",
    "ResumeRequest",
    "SessionManagerProtocol",
    "TakeoverRequest",
    "TaskSnapshot",
    "TaskSubmitRequest",
    "TransitionRecord",
    "create_app",
    "maybe_await",
]
