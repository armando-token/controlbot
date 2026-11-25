# ADR-0002: SQLite WAL Persistence, Short Transactions & Fenced Step Leases

- **Status**: Accepted (M1)
- **Date**: 2026-11-25
- **Owner**: Orquestador e integrador (`teamwork_worker_m1_1`)
- **Governing Specification**: `MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md` (§4.1, §4.3, §4.4, §6.1 `A05`/`A08`/`A09`/`A14`)

---

## Context
Grokbot-clon must survive abrupt worker/coordinator crashes (`SIGKILL` in `A08`, `A14`), enforce shared root+child budgets across concurrent runs (`depth=1`, `2` active children), prevent stale/late worker results after lease loss or cancellation (`A09`), and never double-apply unverified side effects after crashes (`A08`).

## Decision
1. **Storage Engine (`src/storage/`)**:
   - Local-disk SQLite using `PRAGMA journal_mode=WAL;`, `PRAGMA foreign_keys=ON;`, and `PRAGMA busy_timeout=5000;`.
   - **Verified Implementation Constraint**: Python's `sqlite3.Connection.execute()` raises `ProgrammingError` on multi-statement strings (`You can only execute one statement at a time.`). Therefore all PRAGMAs MUST be issued as separate `conn.execute(...)` calls (verified in `src/doctor.py:check_sqlite_wal`).
2. **Short-Transaction Discipline**:
   - Database write transactions cover only state transitions, lease claims, budget reservations/reconciliations, and receipt inserts.
   - **Never** hold an open SQLite write transaction across Playwright browser operations, HTTP lab calls, or LLM inference calls.
3. **Six-Step Lease & Recovery Protocol (Megaplan §4.3)**:
   1. **Reserve work**: Claim step transactionally with `(lease_owner, lease_expiry, lease_generation)`.
   2. **Prepare action**: Validate parameters, permissions, deadline, and allowed effects; persist a stable `operation_key` and attempt record.
   3. **Execute outside DB transaction**: Enforce per-action timeout and separate transport errors from semantic errors.
   4. **Verify and commit**: Run independent verifier against observed before/after state; commit step result and release lease **only if `lease_generation` matches and run status is not terminal**.
   5. **Explicit crash recovery**: On crash between execution and confirmation (`StepStatus.UNKNOWN` / `ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION`), inspect/reconcile target state via `operation_key` before retrying (`read` may re-query if allowed; `effect` deduplicates by `idempotency_key` or escalates to `waiting_for_input` for human review).
   6. **Persistent separation**: Task state and redacted `ActionReceipt`s survive worker loss; a coordinator restart treats active leases by expiry/generation rather than trusting missing completion timestamps (`OpenClaw` lesson).
4. **Transactional Root-Shared Budget Accounting**:
   - Before dispatching model or tool calls, reserve estimated tokens/call slots transactionally on the root task's `BudgetUsage` row, then reconcile with actual (or conservative `estimated`) usage upon completion.

## Alternatives Considered
1. **PostgreSQL from M1**: Rejected for MVP; adds daemon management and packaging weight on single-node/air-gapped Linux setups. `StorageRepo` interface isolates SQLite so PostgreSQL remains a clean swap later.
2. **In-memory queues or JSON state files**: Rejected; cannot enforce atomic shared-budget reservations across concurrent child runs or guarantee crash-safe `SIGKILL` recovery (`A08`, `A14`).
3. **Long-lived transactions wrapping tool I/O**: Rejected; causes `SQLITE_BUSY` contention and blocks cancellations/heartbeats.

## Consequences
- **Positive**: Zero external database daemon, atomic budget/lease fencing, deterministic rejection of stale worker completions, and reproducible `SIGKILL` recovery.
- **Negative / Trade-offs**: SQLite WAL requires local POSIX filesystem locking and **must never** be placed on network filesystems (NFS/SMB). Single-writer throughput limits high-concurrency multi-host scaling.

## Revocation Conditions
- Migrate behind the `StorageRepo` contract to PostgreSQL if multi-host concurrent coordinators, high write-concurrency benchmarks, or high-availability failover become mandatory.
