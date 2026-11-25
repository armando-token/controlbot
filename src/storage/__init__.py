"""SQLite WAL persistence package (F05, F06)."""

from src.storage.db import open_connection, read_transaction, write_transaction
from src.storage.errors import (
    BudgetExceededError,
    ConflictError,
    IdempotencyConflictError,
    LeaseFencingError,
    MigrationError,
    NotFoundError,
    StorageError,
    TerminalStateError,
)
from src.storage.migrations import CURRENT_SCHEMA_VERSION, Migration, apply_migrations
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    is_sensitive_key_strict,
    redact_payload_strict,
    redact_string_strict,
)
from src.storage.repo import (
    AuditRecord,
    BudgetReservation,
    EventRecord,
    OperationKeyRecord,
    RunSnapshot,
    StepExecutionDetails,
    StepSignatureRecord,
    StorageRepo,
)

__all__ = [
    "AuditRecord",
    "BudgetExceededError",
    "BudgetReservation",
    "CURRENT_SCHEMA_VERSION",
    "ConflictError",
    "EventRecord",
    "IdempotencyConflictError",
    "LeaseFencingError",
    "Migration",
    "MigrationError",
    "NotFoundError",
    "OperationKeyRecord",
    "RunSnapshot",
    "StepExecutionDetails",
    "StepSignatureRecord",
    "StorageError",
    "StorageRepo",
    "TerminalStateError",
    "apply_migrations",
    "contains_unredacted_secret_strict",
    "is_sensitive_key_strict",
    "open_connection",
    "read_transaction",
    "redact_payload_strict",
    "redact_string_strict",
    "write_transaction",
]
