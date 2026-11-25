"""Versioned forward SQLite schema migrations (F05)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from src.storage.errors import MigrationError

CURRENT_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class Migration:
    """Single forward schema migration consisting of individual DDL statements."""

    version: int
    name: str
    statements: tuple[str, ...]


_V1_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        facility_id TEXT NOT NULL,
        query TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        backend_mode TEXT NOT NULL,
        read_only INTEGER NOT NULL CHECK (read_only IN (0, 1)),
        spec_json TEXT NOT NULL,
        budget_config_json TEXT NOT NULL,
        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
        cancel_reason TEXT,
        cancel_requested_at TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS task_budgets (
        task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
        active_children INTEGER NOT NULL DEFAULT 0 CHECK (active_children >= 0),
        tool_calls_used INTEGER NOT NULL DEFAULT 0 CHECK (tool_calls_used >= 0),
        tool_calls_reserved INTEGER NOT NULL DEFAULT 0 CHECK (tool_calls_reserved >= 0),
        model_calls_used INTEGER NOT NULL DEFAULT 0 CHECK (model_calls_used >= 0),
        model_calls_reserved INTEGER NOT NULL DEFAULT 0 CHECK (model_calls_reserved >= 0),
        wall_seconds_elapsed REAL NOT NULL DEFAULT 0.0 CHECK (wall_seconds_elapsed >= 0.0),
        human_wait_seconds_elapsed REAL NOT NULL DEFAULT 0.0
            CHECK (human_wait_seconds_elapsed >= 0.0),
        prompt_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK (prompt_tokens_used >= 0),
        completion_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK (completion_tokens_used >= 0),
        tokens_reserved INTEGER NOT NULL DEFAULT 0 CHECK (tokens_reserved >= 0),
        transient_retries_used INTEGER NOT NULL DEFAULT 0 CHECK (transient_retries_used >= 0),
        usage_estimated INTEGER NOT NULL DEFAULT 0 CHECK (usage_estimated IN (0, 1)),
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        parent_run_id TEXT REFERENCES runs(run_id) ON DELETE CASCADE,
        depth INTEGER NOT NULL CHECK (depth >= 0),
        status TEXT NOT NULL,
        attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
        deadline_at TEXT NOT NULL,
        progress REAL NOT NULL DEFAULT 0.0 CHECK (progress >= 0.0 AND progress <= 1.0),
        transition_reason TEXT NOT NULL,
        required_action TEXT,
        scope_json TEXT,
        waiting_since TEXT,
        pending_human_input_json TEXT,
        result_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_runs_task_status ON runs(task_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_runs_parent ON runs(parent_run_id)",
    """
    CREATE TABLE IF NOT EXISTS steps (
        step_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        step_index INTEGER NOT NULL CHECK (step_index >= 0),
        status TEXT NOT NULL,
        attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
        tool_id TEXT NOT NULL,
        redacted_args_json TEXT NOT NULL,
        exec_args_json TEXT NOT NULL,
        target_origin TEXT,
        effect_class TEXT NOT NULL CHECK (effect_class IN ('read', 'effect')),
        operation_key TEXT NOT NULL,
        lease_owner TEXT,
        lease_expiry TEXT,
        lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
        completion_verifier TEXT NOT NULL,
        outcome TEXT,
        step_output_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(run_id, step_index),
        UNIQUE(operation_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_steps_lease ON steps(status, lease_expiry)",
    """
    CREATE TABLE IF NOT EXISTS step_attempts (
        attempt_id TEXT PRIMARY KEY,
        step_id TEXT NOT NULL REFERENCES steps(step_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        attempt INTEGER NOT NULL CHECK (attempt >= 1),
        operation_key TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        lease_generation INTEGER NOT NULL CHECK (lease_generation >= 1),
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(step_id, attempt)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_step_attempts_op ON step_attempts(operation_key)",
    """
    CREATE TABLE IF NOT EXISTS budget_reservations (
        reservation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        step_id TEXT REFERENCES steps(step_id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('tool', 'model')),
        tool_calls_reserved INTEGER NOT NULL DEFAULT 0 CHECK (tool_calls_reserved >= 0),
        model_calls_reserved INTEGER NOT NULL DEFAULT 0 CHECK (model_calls_reserved >= 0),
        tokens_reserved INTEGER NOT NULL DEFAULT 0 CHECK (tokens_reserved >= 0),
        status TEXT NOT NULL CHECK (status IN ('active', 'reconciled', 'released', 'expired')),
        lease_generation INTEGER,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    (
        "CREATE INDEX IF NOT EXISTS idx_budget_res_status "
        "ON budget_reservations(task_id, status, expires_at)"
    ),
    """
    CREATE TABLE IF NOT EXISTS operation_keys (
        operation_key TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        step_id TEXT NOT NULL REFERENCES steps(step_id) ON DELETE CASCADE,
        latest_attempt INTEGER NOT NULL CHECK (latest_attempt >= 1),
        tool_id TEXT NOT NULL,
        effect_class TEXT NOT NULL CHECK (effect_class IN ('read', 'effect')),
        idempotency_key TEXT NOT NULL,
        status TEXT NOT NULL,
        redacted_args_json TEXT NOT NULL,
        reconciliation_note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS action_receipts (
        receipt_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
        step_id TEXT NOT NULL REFERENCES steps(step_id) ON DELETE RESTRICT,
        attempt INTEGER NOT NULL CHECK (attempt >= 1),
        tool_id TEXT NOT NULL,
        operation_key TEXT NOT NULL,
        outcome TEXT NOT NULL,
        duration_ms REAL NOT NULL CHECK (duration_ms >= 0.0),
        receipt_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_receipts_run ON action_receipts(run_id, step_id, attempt)",
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_receipts_no_update
    BEFORE UPDATE ON action_receipts
    BEGIN
        SELECT RAISE(ABORT, 'action_receipts is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_receipts_no_delete
    BEFORE DELETE ON action_receipts
    BEGIN
        SELECT RAISE(ABORT, 'action_receipts is append-only');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS observations (
        observation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        step_id TEXT REFERENCES steps(step_id) ON DELETE SET NULL,
        observation_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id, recorded_at)",
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        run_id TEXT REFERENCES runs(run_id) ON DELETE CASCADE,
        step_id TEXT REFERENCES steps(step_id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        from_status TEXT,
        to_status TEXT,
        reason TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, event_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id, event_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        run_id TEXT,
        step_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        decision TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id, audit_id)",
    """
    CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS step_signatures (
        sig_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
        step_index INTEGER NOT NULL CHECK (step_index >= 0),
        tool_id TEXT NOT NULL,
        target_key TEXT NOT NULL,
        canonical_args_hash TEXT NOT NULL,
        result_hash TEXT NOT NULL,
        progress_token TEXT,
        succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sigs_run ON step_signatures(run_id, sig_id)",
)

_V2_STATEMENTS: tuple[str, ...] = (
    "ALTER TABLE task_budgets ADD COLUMN human_wait_accounted_until TEXT",
)

MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="initial_wal_schema",
        statements=_V1_STATEMENTS,
    ),
    Migration(
        version=2,
        name="human_wait_high_watermark",
        statements=_V2_STATEMENTS,
    ),
)

_REQUIRED_V1_TABLES: frozenset[str] = frozenset(
    {
        "schema_migrations",
        "tasks",
        "task_budgets",
        "runs",
        "steps",
        "step_attempts",
        "budget_reservations",
        "operation_keys",
        "action_receipts",
        "observations",
        "events",
        "audit_log",
        "step_signatures",
    }
)


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Return highest applied schema migration version, or 0 if uninitialized."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    ver_row = conn.execute("SELECT MAX(version) AS max_ver FROM schema_migrations").fetchone()
    if ver_row is None or ver_row["max_ver"] is None:
        return 0
    ver = int(ver_row["max_ver"])
    if ver < 0:
        raise MigrationError(f"Corrupted negative schema version: {ver}")
    return ver


def apply_migrations(conn: sqlite3.Connection, now_iso: str) -> int:
    """Apply all pending forward migrations inside an active write transaction."""
    current = get_schema_version(conn)
    if current > CURRENT_SCHEMA_VERSION:
        raise MigrationError(
            f"Database schema version {current} is newer than supported version "
            f"{CURRENT_SCHEMA_VERSION}."
        )

    if current == CURRENT_SCHEMA_VERSION:
        existing_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        existing_tables = {str(r["name"]) for r in existing_rows}
        missing = _REQUIRED_V1_TABLES - existing_tables
        if missing:
            raise MigrationError(
                f"Schema version {current} is recorded, but required tables are missing: "
                f"{sorted(missing)}"
            )
        return current

    for migration in MIGRATIONS:
        if migration.version <= current:
            continue
        for stmt in migration.statements:
            conn.execute(stmt)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (migration.version, migration.name, now_iso),
        )
        current = migration.version

    return current
