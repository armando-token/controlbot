"""Domain exceptions for the isolated M7 local software factory (F16)."""

from __future__ import annotations


class FactoryError(RuntimeError):
    """Base error for local continuous-improvement factory operations."""


class PolicyImmutabilityError(FactoryError):
    """Raised when a candidate patch attempts to modify immutable policy or acceptance rules."""

    def __init__(self, message: str, offending_paths: tuple[str, ...] = ()) -> None:
        prefix = "POLICY_IMMUTABILITY_VIOLATION"
        formatted = message if prefix in message else f"{prefix}: {message}"
        if offending_paths:
            formatted = f"{formatted} (paths={list(offending_paths)})"
        super().__init__(formatted)
        self.offending_paths = offending_paths


class IsolationBoundaryError(FactoryError):
    """Raised when factory state or candidates violate runtime DB/credential isolation."""

    def __init__(self, message: str) -> None:
        prefix = "ISOLATION_BOUNDARY_VIOLATION"
        formatted = message if prefix in message else f"{prefix}: {message}"
        if "blocked" not in formatted.lower() and "forbidden" not in formatted.lower():
            formatted = f"{formatted} (blocked)"
        super().__init__(formatted)


class DuplicateProposalError(FactoryError):
    """Raised when an already-rejected proposal hash is retried without new evidence."""

    def __init__(self, message: str) -> None:
        prefix = "DUPLICATE_PROPOSAL_REJECTED"
        formatted = message if prefix in message else f"{prefix}: {message}"
        super().__init__(formatted)


class FactoryBudgetError(FactoryError):
    """Raised when factory cycle or attempt budgets are exhausted."""

    def __init__(self, message: str) -> None:
        prefix = "FACTORY_BUDGET_EXHAUSTED"
        formatted = message if prefix in message else f"{prefix}: {message}"
        super().__init__(formatted)


class FactoryLeaseError(FactoryError):
    """Raised on lease contention or stale-generation fencing violations."""
