"""Strictly isolated SQLite WAL persistence for the M7 software factory (F16)."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any

from src.contracts.common import ensure_utc, utc_now
from src.factory.errors import FactoryError, FactoryLeaseError, IsolationBoundaryError
from src.factory.models import (
    BacklogItem,
    CandidateRunRecord,
    CycleBudget,
    FactoryLease,
    LessonRecord,
    RollbackManifest,
)

_RUNTIME_TABLES: frozenset[str] = frozenset({"tasks", "runs", "steps", "action_receipts"})
_FORBIDDEN_DIR_MARKERS: tuple[str, ...] = (".grokbot_profiles", "browser_profiles")


def open_factory_connection(db_path: Path) -> sqlite3.Connection:
    """Open isolated factory SQLite connection with separate WAL/FK/busy_timeout PRAGMAs."""
    resolved = Path(db_path)
    if not resolved.parent.exists():
        resolved.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        conn = sqlite3.connect(
            str(resolved),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
    except sqlite3.Error as exc:
        raise FactoryError(f"Failed to open factory SQLite database at {resolved}: {exc}") from exc

    conn.row_factory = sqlite3.Row
    try:
        journal_row = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error as exc:
        conn.close()
        raise FactoryError(
            f"Failed to configure factory SQLite PRAGMAs on {resolved}: {exc}"
        ) from exc

    if str(resolved) != ":memory:":
        mode = str(journal_row[0]).lower() if journal_row is not None else ""
        if mode != "wal":
            conn.close()
            raise FactoryError(
                f"Factory SQLite WAL mode could not be enabled on {resolved} (got {mode!r})."
            )
    return conn


def _parse_iso_utc(raw: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(raw))


class FactoryStore:
    """Isolated SQLite WAL store for factory backlog, leases, budgets, lessons, and manifests."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        clock: Callable[[], datetime] = utc_now,
        forbidden_db_paths: Sequence[Path | str] = (),
        forbidden_credential_paths: Sequence[Path | str] = (),
    ) -> None:
        self._db_path = Path(db_path).resolve()
        self._clock = clock
        self._lock = RLock()

        forbidden_dbs: set[Path] = {Path(p).resolve() for p in forbidden_db_paths}
        env_runtime_db = os.environ.get("GROKBOT_DB_PATH", "").strip()
        if env_runtime_db:
            forbidden_dbs.add(Path(env_runtime_db).resolve())
        forbidden_creds: set[Path] = {Path(p).resolve() for p in forbidden_credential_paths}

        if self._db_path in forbidden_dbs:
            raise IsolationBoundaryError(
                f"ISOLATION_BOUNDARY_VIOLATION: blocked factory DB {self._db_path} "
                "matching forbidden industrial runtime DB."
            )
        for cred_path in forbidden_creds:
            if self._db_path == cred_path or self._db_path.is_relative_to(cred_path):
                raise IsolationBoundaryError(
                    f"ISOLATION_BOUNDARY_VIOLATION: blocked factory DB {self._db_path} "
                    f"inside forbidden credential path {cred_path}."
                )
        for marker in _FORBIDDEN_DIR_MARKERS:
            if marker in self._db_path.parts:
                raise IsolationBoundaryError(
                    f"ISOLATION_BOUNDARY_VIOLATION: blocked factory DB {self._db_path} "
                    f"inside industrial browser profile directory ({marker})."
                )

    @property
    def db_path(self) -> Path:
        return self._db_path

    @contextmanager
    def _write_tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = open_factory_connection(self._db_path)
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
    def _read_tx(self) -> Iterator[sqlite3.Connection]:
        conn = open_factory_connection(self._db_path)
        try:
            conn.execute("BEGIN;")
            yield conn
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create isolated factory schema with 0o700 dir / 0o600 file permissions."""
        parent = self._db_path.parent
        created_parent = not parent.exists()
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if created_parent and os.name == "posix":
            os.chmod(parent, 0o700)

        with self._write_tx() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
            existing_tables = {str(r["name"]) for r in rows}
            overlap = sorted(existing_tables & _RUNTIME_TABLES)
            if overlap:
                raise IsolationBoundaryError(
                    "ISOLATION_BOUNDARY_VIOLATION: blocked factory DB sharing industrial "
                    f"runtime tables {overlap}."
                )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_backlog (
                    item_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    hypothesis TEXT NOT NULL,
                    target_metric TEXT NOT NULL,
                    baseline_repro_cmd TEXT NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    attempts_used INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_leases (
                    lease_id TEXT PRIMARY KEY,
                    item_id TEXT NOT NULL REFERENCES factory_backlog(item_id),
                    owner TEXT NOT NULL,
                    expiry TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK(generation >= 1),
                    status TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_budgets (
                    budget_id TEXT PRIMARY KEY,
                    max_cycles INTEGER NOT NULL,
                    cycles_used INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL,
                    attempts_used INTEGER NOT NULL DEFAULT 0,
                    max_wall_seconds REAL NOT NULL,
                    wall_seconds_used REAL NOT NULL DEFAULT 0.0,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_candidates (
                    run_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    branch_name TEXT NOT NULL,
                    base_commit TEXT NOT NULL,
                    candidate_commit TEXT,
                    proposal_hash TEXT NOT NULL,
                    baseline_metric REAL,
                    candidate_metric REAL,
                    baseline_passed INTEGER NOT NULL,
                    regression_passed INTEGER NOT NULL,
                    identity_gate_passed INTEGER NOT NULL,
                    policy_passed INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    manifest_json TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_lessons (
                    lesson_id TEXT PRIMARY KEY,
                    item_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    proposal_hash TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    regression_test_path TEXT,
                    reopen_condition TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_manifests (
                    manifest_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    previous_commit TEXT NOT NULL,
                    new_commit TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    rolled_back INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS factory_audit_log (
                    audit_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

        if os.name == "posix" and self._db_path.exists():
            os.chmod(self._db_path, 0o600)

    def add_backlog_item(self, item: BacklogItem) -> BacklogItem:
        now = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            conn.execute(
                """
                INSERT INTO factory_backlog (
                    item_id, title, priority, status, hypothesis, target_metric,
                    baseline_repro_cmd, max_attempts, attempts_used, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(item_id) DO UPDATE SET
                    title=excluded.title,
                    priority=excluded.priority,
                    hypothesis=excluded.hypothesis,
                    target_metric=excluded.target_metric,
                    baseline_repro_cmd=excluded.baseline_repro_cmd,
                    max_attempts=excluded.max_attempts,
                    updated_at=excluded.updated_at;
                """,
                (
                    item.item_id,
                    item.title,
                    item.priority,
                    item.status,
                    item.hypothesis,
                    item.target_metric,
                    item.baseline_repro_cmd,
                    item.max_attempts,
                    item.attempts_used,
                    ensure_utc(item.created_at).isoformat(),
                    now,
                ),
            )
        loaded = self.get_backlog_item(item.item_id)
        assert loaded is not None
        return loaded

    def get_backlog_item(self, item_id: str) -> BacklogItem | None:
        with self._read_tx() as conn:
            row = conn.execute(
                "SELECT * FROM factory_backlog WHERE item_id = ?;",
                (item_id,),
            ).fetchone()
        return self._row_to_backlog_item(row) if row is not None else None

    def list_backlog_items(self) -> list[BacklogItem]:
        with self._read_tx() as conn:
            rows = conn.execute(
                "SELECT * FROM factory_backlog ORDER BY priority ASC, created_at ASC;"
            ).fetchall()
        return [self._row_to_backlog_item(r) for r in rows]

    def get_next_pending_item(self) -> BacklogItem | None:
        with self._read_tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM factory_backlog
                WHERE status IN ('pending', 'in_progress')
                ORDER BY priority ASC, created_at ASC
                LIMIT 1;
                """
            ).fetchone()
        return self._row_to_backlog_item(row) if row is not None else None

    def set_backlog_status(
        self,
        item_id: str,
        status: str,
    ) -> None:
        now = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            conn.execute(
                "UPDATE factory_backlog SET status = ?, updated_at = ? WHERE item_id = ?;",
                (status, now, item_id),
            )

    def ensure_budget(self, budget: CycleBudget | None = None) -> CycleBudget:
        target = budget or CycleBudget()
        now = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            existing = conn.execute(
                "SELECT * FROM factory_budgets WHERE budget_id = ?;",
                (target.budget_id,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO factory_budgets (
                        budget_id, max_cycles, cycles_used, max_attempts, attempts_used,
                        max_wall_seconds, wall_seconds_used, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        target.budget_id,
                        target.max_cycles,
                        target.cycles_used,
                        target.max_attempts,
                        target.attempts_used,
                        target.max_wall_seconds,
                        target.wall_seconds_used,
                        now,
                    ),
                )
                return target
            return self._row_to_budget(existing)

    def get_budget(self, budget_id: str = "default") -> CycleBudget:
        with self._read_tx() as conn:
            row = conn.execute(
                "SELECT * FROM factory_budgets WHERE budget_id = ?;",
                (budget_id,),
            ).fetchone()
        if row is None:
            return self.ensure_budget(CycleBudget(budget_id=budget_id))
        return self._row_to_budget(row)

    def acquire_lease(
        self,
        item_id: str,
        owner: str,
        *,
        ttl_s: float = 60.0,
    ) -> FactoryLease:
        now_dt = ensure_utc(self._clock())
        now_iso = now_dt.isoformat()
        expiry_dt = now_dt + timedelta(seconds=ttl_s)
        expiry_iso = expiry_dt.isoformat()
        lease_id = f"flease-{uuid.uuid4().hex[:12]}"

        with self._write_tx() as conn:
            item_row = conn.execute(
                "SELECT * FROM factory_backlog WHERE item_id = ?;",
                (item_id,),
            ).fetchone()
            if item_row is None:
                raise FactoryLeaseError(f"Cannot lease unknown backlog item {item_id!r}.")

            active_rows = conn.execute(
                """
                SELECT * FROM factory_leases
                WHERE item_id = ? AND status = 'active'
                ORDER BY generation DESC;
                """,
                (item_id,),
            ).fetchall()
            for row in active_rows:
                row_expiry = _parse_iso_utc(str(row["expiry"]))
                if row_expiry > now_dt:
                    raise FactoryLeaseError(
                        f"Backlog item {item_id!r} already leased by {row['owner']!r} "
                        f"(generation={row['generation']})."
                    )
                conn.execute(
                    "UPDATE factory_leases SET status = 'expired', updated_at = ? "
                    "WHERE lease_id = ?;",
                    (now_iso, row["lease_id"]),
                )

            max_gen_row = conn.execute(
                "SELECT COALESCE(MAX(generation), 0) AS max_gen "
                "FROM factory_leases WHERE item_id = ?;",
                (item_id,),
            ).fetchone()
            next_gen = int(max_gen_row["max_gen"]) + 1 if max_gen_row is not None else 1

            conn.execute(
                """
                INSERT INTO factory_leases (
                    lease_id, item_id, owner, expiry, generation, status, acquired_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?);
                """,
                (lease_id, item_id, owner, expiry_iso, next_gen, now_iso, now_iso),
            )
            conn.execute(
                "UPDATE factory_backlog SET status = 'in_progress', updated_at = ? "
                "WHERE item_id = ?;",
                (now_iso, item_id),
            )

        return FactoryLease(
            lease_id=lease_id,
            item_id=item_id,
            owner=owner,
            expiry=expiry_dt,
            generation=next_gen,
            status="active",
            acquired_at=now_dt,
            updated_at=now_dt,
        )

    def renew_lease(
        self,
        lease_id: str,
        owner: str,
        generation: int,
        *,
        ttl_s: float = 60.0,
    ) -> FactoryLease:
        now_dt = ensure_utc(self._clock())
        now_iso = now_dt.isoformat()
        expiry_dt = now_dt + timedelta(seconds=ttl_s)
        with self._write_tx() as conn:
            row = conn.execute(
                "SELECT * FROM factory_leases WHERE lease_id = ?;",
                (lease_id,),
            ).fetchone()
            if row is None:
                raise FactoryLeaseError(f"Unknown lease {lease_id!r}.")
            if (
                row["status"] != "active"
                or int(row["generation"]) != generation
                or row["owner"] != owner
            ):
                raise FactoryLeaseError(
                    f"Stale or mismatched lease {lease_id!r} (gen={generation}, owner={owner!r})."
                )
            if _parse_iso_utc(str(row["expiry"])) <= now_dt:
                conn.execute(
                    "UPDATE factory_leases SET status = 'expired', updated_at = ? "
                    "WHERE lease_id = ?;",
                    (now_iso, lease_id),
                )
                raise FactoryLeaseError(f"Lease {lease_id!r} expired before renewal.")
            conn.execute(
                "UPDATE factory_leases SET expiry = ?, updated_at = ? WHERE lease_id = ?;",
                (expiry_dt.isoformat(), now_iso, lease_id),
            )
            updated = conn.execute(
                "SELECT * FROM factory_leases WHERE lease_id = ?;",
                (lease_id,),
            ).fetchone()
            assert updated is not None
        return self._row_to_lease(updated)

    def release_lease(self, lease_id: str, generation: int) -> None:
        now_iso = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            row = conn.execute(
                "SELECT * FROM factory_leases WHERE lease_id = ?;",
                (lease_id,),
            ).fetchone()
            if row is None:
                raise FactoryLeaseError(f"Unknown lease {lease_id!r}.")
            if int(row["generation"]) != generation:
                raise FactoryLeaseError(
                    f"Lease generation mismatch for {lease_id!r}: "
                    f"expected {row['generation']}, got {generation}."
                )
            if row["status"] != "active":
                raise FactoryLeaseError(
                    f"Lease {lease_id!r} is no longer active (status={row['status']!r})."
                )
            conn.execute(
                "UPDATE factory_leases SET status = 'released', updated_at = ? "
                "WHERE lease_id = ?;",
                (now_iso, lease_id),
            )

    def get_active_lease(self, item_id: str) -> FactoryLease | None:
        now_dt = ensure_utc(self._clock())
        with self._read_tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM factory_leases
                WHERE item_id = ? AND status = 'active'
                ORDER BY generation DESC
                LIMIT 1;
                """,
                (item_id,),
            ).fetchone()
        if row is None:
            return None
        lease = self._row_to_lease(row)
        if lease.expiry <= now_dt:
            return None
        return lease

    def commit_candidate_attempt(
        self,
        *,
        lease: FactoryLease,
        record: CandidateRunRecord,
        lesson: LessonRecord,
        manifest: RollbackManifest | None = None,
        wall_seconds_delta: float = 0.0,
        budget_id: str = "default",
    ) -> None:
        """Atomically fence lease generation, increment budgets/attempts, and persist records."""
        now_dt = ensure_utc(self._clock())
        now_iso = now_dt.isoformat()
        with self._write_tx() as conn:
            lease_row = conn.execute(
                "SELECT * FROM factory_leases WHERE lease_id = ?;",
                (lease.lease_id,),
            ).fetchone()
            if lease_row is None:
                raise FactoryLeaseError(f"Unknown lease {lease.lease_id!r}.")
            if lease_row["status"] != "active":
                raise FactoryLeaseError(
                    f"Lease {lease.lease_id!r} is not active (status={lease_row['status']!r})."
                )
            if int(lease_row["generation"]) != lease.generation:
                raise FactoryLeaseError(
                    f"Stale lease generation {lease.generation} for {lease.lease_id!r}."
                )
            if _parse_iso_utc(str(lease_row["expiry"])) <= now_dt:
                conn.execute(
                    "UPDATE factory_leases SET status = 'expired', updated_at = ? "
                    "WHERE lease_id = ?;",
                    (now_iso, lease.lease_id),
                )
                raise FactoryLeaseError(f"Lease {lease.lease_id!r} expired before commit.")

            item_row = conn.execute(
                "SELECT * FROM factory_backlog WHERE item_id = ?;",
                (record.item_id,),
            ).fetchone()
            if item_row is None:
                raise FactoryError(f"Unknown backlog item {record.item_id!r}.")
            new_item_attempts = int(item_row["attempts_used"]) + 1
            if record.status == "PROMOTED":
                new_item_status = "completed"
            elif new_item_attempts >= int(item_row["max_attempts"]):
                new_item_status = "paused"
            else:
                new_item_status = "pending"

            conn.execute(
                """
                UPDATE factory_backlog
                SET attempts_used = ?, status = ?, updated_at = ?
                WHERE item_id = ?;
                """,
                (new_item_attempts, new_item_status, now_iso, record.item_id),
            )

            budget_row = conn.execute(
                "SELECT * FROM factory_budgets WHERE budget_id = ?;",
                (budget_id,),
            ).fetchone()
            if budget_row is None:
                conn.execute(
                    """
                    INSERT INTO factory_budgets (
                        budget_id, max_cycles, cycles_used, max_attempts, attempts_used,
                        max_wall_seconds, wall_seconds_used, updated_at
                    ) VALUES (?, 4, 1, 2, 1, 300.0, ?, ?);
                    """,
                    (budget_id, max(0.0, wall_seconds_delta), now_iso),
                )
            else:
                conn.execute(
                    """
                    UPDATE factory_budgets
                    SET cycles_used = cycles_used + 1,
                        attempts_used = attempts_used + 1,
                        wall_seconds_used = wall_seconds_used + ?,
                        updated_at = ?
                    WHERE budget_id = ?;
                    """,
                    (max(0.0, wall_seconds_delta), now_iso, budget_id),
                )

            manifest_json = manifest.model_dump_json() if manifest is not None else None
            conn.execute(
                """
                INSERT INTO factory_candidates (
                    run_id, candidate_id, item_id, branch_name, base_commit, candidate_commit,
                    proposal_hash, baseline_metric, candidate_metric,
                    baseline_passed, regression_passed, identity_gate_passed, policy_passed,
                    status, reason, manifest_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record.run_id,
                    record.candidate_id,
                    record.item_id,
                    record.branch_name,
                    record.base_commit,
                    record.candidate_commit,
                    record.proposal_hash,
                    record.baseline_metric,
                    record.candidate_metric,
                    int(record.baseline_passed),
                    int(record.regression_passed),
                    int(record.identity_gate_passed),
                    int(record.policy_passed),
                    record.status,
                    record.reason,
                    manifest_json,
                    ensure_utc(record.created_at).isoformat(),
                ),
            )
            conn.execute(
                """
                INSERT INTO factory_lessons (
                    lesson_id, item_id, candidate_id, proposal_hash, outcome,
                    reason, regression_test_path, reopen_condition, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    lesson.lesson_id,
                    lesson.item_id,
                    lesson.candidate_id,
                    lesson.proposal_hash,
                    lesson.outcome,
                    lesson.reason,
                    lesson.regression_test_path,
                    lesson.reopen_condition,
                    ensure_utc(lesson.created_at).isoformat(),
                ),
            )
            if manifest is not None:
                manifest_id = f"fman-{manifest.candidate_id}-{uuid.uuid4().hex[:8]}"
                conn.execute(
                    """
                    INSERT INTO factory_manifests (
                        manifest_id, candidate_id, previous_commit, new_commit,
                        manifest_json, rolled_back, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, ?, ?);
                    """,
                    (
                        manifest_id,
                        manifest.candidate_id,
                        manifest.previous_commit,
                        manifest.new_commit,
                        manifest.model_dump_json(),
                        now_iso,
                        now_iso,
                    ),
                )

            conn.execute(
                "UPDATE factory_leases SET status = 'released', updated_at = ? WHERE lease_id = ?;",
                (now_iso, lease.lease_id),
            )
            conn.execute(
                """
                INSERT INTO factory_audit_log (
                    audit_id, actor, action, decision, detail_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    f"faud-{uuid.uuid4().hex[:12]}",
                    lease.owner,
                    f"candidate_{record.status.lower()}",
                    "allow" if record.status == "PROMOTED" else "deny",
                    json.dumps(
                        {
                            "candidate_id": record.candidate_id,
                            "item_id": record.item_id,
                            "branch": record.branch_name,
                            "reason": record.reason,
                        }
                    ),
                    now_iso,
                ),
            )

    def has_rejected_proposal(self, proposal_hash: str) -> bool:
        with self._read_tx() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM factory_candidates
                WHERE proposal_hash = ? AND status = 'REJECTED'
                LIMIT 1;
                """,
                (proposal_hash,),
            ).fetchone()
        return row is not None

    def list_lessons(self) -> list[LessonRecord]:
        with self._read_tx() as conn:
            rows = conn.execute(
                "SELECT * FROM factory_lessons ORDER BY created_at ASC;"
            ).fetchall()
        return [
            LessonRecord(
                lesson_id=str(r["lesson_id"]),
                item_id=str(r["item_id"]),
                candidate_id=str(r["candidate_id"]),
                proposal_hash=str(r["proposal_hash"]),
                outcome=r["outcome"],
                reason=str(r["reason"]),
                regression_test_path=r["regression_test_path"],
                reopen_condition=r["reopen_condition"],
                created_at=_parse_iso_utc(str(r["created_at"])),
            )
            for r in rows
        ]

    def list_candidate_runs(self) -> list[CandidateRunRecord]:
        with self._read_tx() as conn:
            rows = conn.execute(
                "SELECT * FROM factory_candidates ORDER BY created_at ASC;"
            ).fetchall()
        return [
            CandidateRunRecord(
                run_id=str(r["run_id"]),
                candidate_id=str(r["candidate_id"]),
                item_id=str(r["item_id"]),
                branch_name=str(r["branch_name"]),
                base_commit=str(r["base_commit"]),
                candidate_commit=r["candidate_commit"],
                proposal_hash=str(r["proposal_hash"]),
                baseline_metric=r["baseline_metric"],
                candidate_metric=r["candidate_metric"],
                baseline_passed=bool(r["baseline_passed"]),
                regression_passed=bool(r["regression_passed"]),
                identity_gate_passed=bool(r["identity_gate_passed"]),
                policy_passed=bool(r["policy_passed"]),
                status=r["status"],
                reason=str(r["reason"]),
                created_at=_parse_iso_utc(str(r["created_at"])),
            )
            for r in rows
        ]

    def mark_manifest_rolled_back(self, candidate_id: str) -> None:
        now_iso = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            conn.execute(
                """
                UPDATE factory_manifests
                SET rolled_back = 1, updated_at = ?
                WHERE candidate_id = ?;
                """,
                (now_iso, candidate_id),
            )
            conn.execute(
                """
                INSERT INTO factory_audit_log (
                    audit_id, actor, action, decision, detail_json, created_at
                ) VALUES (?, 'factory', 'rollback_manifest', 'allow', ?, ?);
                """,
                (
                    f"faud-{uuid.uuid4().hex[:12]}",
                    json.dumps({"candidate_id": candidate_id}),
                    now_iso,
                ),
            )

    def append_audit_log(
        self,
        *,
        actor: str,
        action: str,
        decision: str,
        detail: dict[str, Any],
    ) -> None:
        now_iso = ensure_utc(self._clock()).isoformat()
        with self._write_tx() as conn:
            conn.execute(
                """
                INSERT INTO factory_audit_log (
                    audit_id, actor, action, decision, detail_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    f"faud-{uuid.uuid4().hex[:12]}",
                    actor,
                    action,
                    decision,
                    json.dumps(detail),
                    now_iso,
                ),
            )

    @staticmethod
    def _row_to_backlog_item(row: sqlite3.Row) -> BacklogItem:
        return BacklogItem(
            item_id=str(row["item_id"]),
            title=str(row["title"]),
            priority=int(row["priority"]),
            status=row["status"],
            hypothesis=str(row["hypothesis"]),
            target_metric=str(row["target_metric"]),
            baseline_repro_cmd=str(row["baseline_repro_cmd"]),
            max_attempts=int(row["max_attempts"]),
            attempts_used=int(row["attempts_used"]),
            created_at=_parse_iso_utc(str(row["created_at"])),
            updated_at=_parse_iso_utc(str(row["updated_at"])),
        )

    @staticmethod
    def _row_to_budget(row: sqlite3.Row) -> CycleBudget:
        return CycleBudget(
            budget_id=str(row["budget_id"]),
            max_cycles=int(row["max_cycles"]),
            cycles_used=int(row["cycles_used"]),
            max_attempts=int(row["max_attempts"]),
            attempts_used=int(row["attempts_used"]),
            max_wall_seconds=float(row["max_wall_seconds"]),
            wall_seconds_used=float(row["wall_seconds_used"]),
        )

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> FactoryLease:
        return FactoryLease(
            lease_id=str(row["lease_id"]),
            item_id=str(row["item_id"]),
            owner=str(row["owner"]),
            expiry=_parse_iso_utc(str(row["expiry"])),
            generation=int(row["generation"]),
            status=row["status"],
            acquired_at=_parse_iso_utc(str(row["acquired_at"])),
            updated_at=_parse_iso_utc(str(row["updated_at"])),
        )
