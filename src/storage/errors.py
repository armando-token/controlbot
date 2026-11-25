"""Explicit storage and concurrency errors for SQLite WAL persistence."""

from __future__ import annotations


class StorageError(RuntimeError):
    """Base error for storage subsystem failures."""


class MigrationError(StorageError):
    """Raised when schema migrations fail or encounter an incompatible version."""


class NotFoundError(StorageError):
    """Raised when a requested task, run, step, or reservation does not exist."""


class ConflictError(StorageError):
    """Raised when a transactional precondition or optimistic version check fails."""


class LeaseFencingError(ConflictError):
    """Raised when a worker attempts to mutate or commit with a stale or lost lease."""


class TerminalStateError(ConflictError):
    """Raised when attempting to mutate or reopen a terminal or cancelled run."""


class BudgetExceededError(ConflictError):
    """Raised when a budget reservation or child/depth limit would be exceeded."""


class IdempotencyConflictError(ConflictError):
    """Raised on conflicting operation/idempotency state."""
