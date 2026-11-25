"""SQLite WAL connection and short-transaction helpers (ADR-0002)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock

from src.storage.errors import StorageError


def open_connection(db_path: Path) -> sqlite3.Connection:
    """Open a local SQLite connection with separate WAL/FK/busy_timeout PRAGMAs."""
    resolved = Path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(
            str(resolved),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
    except sqlite3.Error as exc:
        raise StorageError(f"Failed to open SQLite database at {resolved}: {exc}") from exc

    conn.row_factory = sqlite3.Row
    try:
        # Execute each PRAGMA in a separate conn.execute() call (ADR-0002 / Python sqlite3).
        journal_row = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error as exc:
        conn.close()
        raise StorageError(f"Failed to configure SQLite PRAGMAs on {resolved}: {exc}") from exc

    if str(resolved) != ":memory:":
        mode = str(journal_row[0]).lower() if journal_row is not None else ""
        if mode != "wal":
            conn.close()
            raise StorageError(
                f"SQLite WAL mode could not be enabled on {resolved} (got {mode!r})."
            )

    return conn


@contextmanager
def write_transaction(db_path: Path, lock: RLock) -> Iterator[sqlite3.Connection]:
    """Acquire intra-process lock, open short connection, and execute BEGIN IMMEDIATE tx."""
    with lock:
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()


@contextmanager
def read_transaction(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Open short-lived read-only snapshot transaction."""
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN;")
        yield conn
        if conn.in_transaction:
            conn.execute("ROLLBACK;")
    finally:
        conn.close()
