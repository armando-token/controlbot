"""N1 unit tests for SQLite WAL storage, migrations, redaction, and concurrency (F05, F06)."""

from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import DataQuality, EffectClass, ReceiptOutcome, StepStatus, TaskStatus
from src.contracts.models import ActionReceipt, Observation, Result, TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model.emulator import EmulatedModelClient
from src.storage import (
    BudgetExceededError,
    MigrationError,
    StorageRepo,
    contains_unredacted_secret_strict,
    open_connection,
    redact_string_strict,
)


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _make_task(
    task_id: str = "task-wal-1",
    *,
    budget: BudgetConfig | None = None,
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        user_id="user-1",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_areas=("area-1",),
            allowed_tools=("read_scada",),
            read_only=True,
        ),
        query="Check pump 34 pressure",
        budget=budget or BudgetConfig(),
    )


@pytest.mark.n1
def test_init_db_pragmas_and_idempotency(tmp_path: Path) -> None:
    db_path = tmp_path / "state" / "grokbot.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)

    v1 = repo.init_db()
    assert v1 == 1
    pragmas = repo.get_pragma_settings()
    assert pragmas["journal_mode"] == "wal"
    assert pragmas["foreign_keys"] == 1
    assert pragmas["busy_timeout"] == 5000

    # Re-opening and re-running init_db() is idempotent
    repo2 = StorageRepo(db_path, clock=clock)
    assert repo2.init_db() == 1


@pytest.mark.n1
def test_schema_migrations_idempotent_and_future_version_fails(tmp_path: Path) -> None:
    db_path = tmp_path / "migrations.db"
    repo = StorageRepo(db_path)
    assert repo.init_db() == 1
    assert repo.init_db() == 1

    # Simulate incompatible future schema version
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (99, "future_v99", "2026-11-25T10:00:00+00:00"),
        )
        conn.execute("COMMIT;")
    finally:
        conn.close()

    with pytest.raises(MigrationError, match="newer than supported"):
        repo.init_db()


@pytest.mark.n1
def test_crud_and_fk_integrity_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "crud.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    task_spec, root_run = repo.create_task_and_run(_make_task())
    assert root_run.depth == 0
    assert root_run.status == TaskStatus.QUEUED

    running_root = repo.transition_run_status(root_run.run_id, TaskStatus.RUNNING, "started")
    assert running_root.version == 2

    child_run = repo.create_child_run(root_run.run_id, "child-1")
    assert child_run.depth == 1
    assert child_run.parent_run_id == root_run.run_id

    step = repo.enqueue_step(
        root_run.run_id,
        "read_scada",
        {"asset": "pump-34"},
        "scada_verifier",
        EffectClass.READ,
        target_origin="https://scada.local",
    )
    leased = repo.acquire_step_lease("worker-1", 30.0, run_id=root_run.run_id)
    assert leased is not None and leased.step_id == step.step_id
    assert leased.lease_generation == 1

    prepared = repo.prepare_step_attempt(
        leased.step_id, leased.lease_generation, leased.operation_key
    )
    assert prepared.status == StepStatus.PREPARED
    op_rec = repo.get_operation_key(leased.operation_key)
    assert op_rec is not None and op_rec.latest_attempt == 1

    executing = repo.mark_step_executing(leased.step_id, leased.lease_generation)
    assert executing.status == StepStatus.EXECUTING

    receipt = ActionReceipt(
        receipt_id="rcpt-1",
        task_id=task_spec.task_id,
        run_id=root_run.run_id,
        step_id=leased.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=leased.operation_key,
        observed_after={"pressure": 4.2},
        duration_ms=12.5,
        evidence_refs=("https://scada.local/readings/34",),
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    committed = repo.commit_step_result(
        leased.step_id,
        leased.lease_generation,
        StepStatus.SUCCEEDED,
        "succeeded",
        receipt,
        step_output={"pressure": 4.2},
        expected_worker="worker-1",
    )
    assert committed.status == StepStatus.SUCCEEDED
    assert committed.lease_owner is None
    assert committed.lease_generation == 1

    obs = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="pump-34",
        observed_label="pressure",
        value=4.2,
        unit="bar",
        source_time=clock(),
        observed_at=clock(),
        quality=DataQuality.GOOD,
    )
    repo.append_observations(
        task_id=task_spec.task_id,
        run_id=root_run.run_id,
        step_id=leased.step_id,
        observations=[obs],
    )
    final_res = Result(
        task_id=task_spec.task_id,
        run_id=root_run.run_id,
        status=TaskStatus.SUCCEEDED,
        answer="Pressure is 4.2 bar",
        verified_observations=(obs,),
    )
    repo.transition_run_status(root_run.run_id, TaskStatus.SUCCEEDED, "done", result=final_res)

    snap = repo.get_run_snapshot(root_run.run_id)
    assert snap.task_spec == task_spec
    assert snap.run.status == TaskStatus.SUCCEEDED
    assert len(snap.steps) == 1
    assert len(snap.receipts) == 1
    assert len(snap.observations) == 1
    assert len(snap.child_runs) == 1
    assert snap.result == final_res

    # FK constraint check: bogus task_id on events fails
    conn = open_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO events (
                    task_id, event_type, reason, payload_json, created_at
                ) VALUES ('nonexistent', 'x', 'y', '{}', '2026-11-25T10:00:00+00:00')
                """
            )
    finally:
        conn.close()


@pytest.mark.n1
def test_append_only_receipts_audit_and_fail_closed_redaction(tmp_path: Path) -> None:
    db_path = tmp_path / "redaction.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()
    task_spec, run = repo.create_task_and_run(_make_task())
    step = repo.enqueue_step(
        run.run_id, "read_scada", {"asset": "pump-34"}, "v", EffectClass.READ
    )

    # camelCase secret key in observed_after must be rejected fail-closed
    bad_camel_receipt = ActionReceipt(
        receipt_id="rcpt-bad-camel",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=step.operation_key,
        observed_after={"accessToken": "super-secret-jwt"},
        duration_ms=1.0,
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    with pytest.raises(ValueError, match="unredacted secret"):
        repo.append_receipt(bad_camel_receipt)

    # Unredacted userinfo / query token in evidence_refs must be rejected fail-closed
    bad_ref_receipt = ActionReceipt(
        receipt_id="rcpt-bad-ref",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=step.operation_key,
        duration_ms=1.0,
        evidence_refs=("https://op:hunter2@scada.local/alarms",),
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    with pytest.raises(ValueError, match="unredacted secret"):
        repo.append_receipt(bad_ref_receipt)

    # Valid redacted receipt stores cleanly without mutating caller dicts
    orig_args = {"asset": "pump-34"}
    good_receipt = ActionReceipt(
        receipt_id="rcpt-good",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args=orig_args,
        operation_key=step.operation_key,
        duration_ms=5.0,
        evidence_refs=("https://[REDACTED]:[REDACTED]@scada.local/alarms",),
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    repo.append_receipt(good_receipt)
    assert orig_args == {"asset": "pump-34"}

    # Audit log & events automatically redact camelCase & Bearer secrets
    repo.append_audit_log(
        task_id=task_spec.task_id,
        run_id=run.run_id,
        actor="test",
        action="check_secret",
        decision="deny",
        detail={
            "sessionToken": "secret-session-123",
            "header": "Bearer top-secret-bearer",
            "url": "https://admin:pw123@scada.local/login",
        },
    )
    audits = repo.list_audit_logs(task_id=task_spec.task_id)
    assert len(audits) == 1
    assert audits[0].detail["sessionToken"] == "[REDACTED]"
    assert audits[0].detail["header"] == "Bearer [REDACTED]"
    assert audits[0].detail["url"] == "https://[REDACTED]:[REDACTED]@scada.local/login"

    # Append-only triggers prevent UPDATE / DELETE on action_receipts and audit_log
    conn = open_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE action_receipts SET outcome = 'hacked'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM action_receipts")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE audit_log SET decision = 'allow'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_log")
    finally:
        conn.close()

    # Bool rejection on float durations
    with pytest.raises(ValueError, match="numeric float"):
        repo.update_wall_seconds(task_spec.task_id, True)
    with pytest.raises(ValueError, match="numeric float"):
        repo.acquire_step_lease("w1", True)


@pytest.mark.n1
def test_wal_concurrency_atomic_lease_and_budget_serialization(tmp_path: Path) -> None:
    db_path = tmp_path / "concurrency.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    tight_budget = BudgetConfig(max_tool_calls=3, max_active_children=2)
    task_spec, root_run = repo.create_task_and_run(_make_task("task-race", budget=tight_budget))
    repo.transition_run_status(root_run.run_id, TaskStatus.RUNNING, "started")
    step = repo.enqueue_step(
        root_run.run_id, "read_scada", {"asset": "pump-34"}, "v", EffectClass.READ
    )

    # 8 concurrent workers race to claim the single step lease
    def claim_worker(idx: int) -> str | None:
        claimed = repo.acquire_step_lease(f"worker-{idx}", 30.0, step_id=step.step_id)
        return claimed.lease_owner if claimed is not None else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = [w for w in pool.map(claim_worker, range(8)) if w is not None]
    assert len(winners) == 1

    # 8 concurrent threads race to reserve 1 tool call against max_tool_calls=3
    def reserve_worker(_: int) -> bool:
        try:
            repo.reserve_budget(task_spec.task_id, root_run.run_id, "tool", tool_calls=1)
            return True
        except BudgetExceededError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve_worker, range(8)))

    assert sum(1 for ok in results if ok) == 3
    usage = repo.get_budget_usage(task_spec.task_id)
    assert usage.tool_calls_reserved == 3

    # 6 concurrent threads race to spawn child runs against max_active_children=2
    def spawn_worker(idx: int) -> bool:
        try:
            repo.create_child_run(root_run.run_id, f"child-race-{idx}")
            return True
        except BudgetExceededError:
            return False

    with ThreadPoolExecutor(max_workers=6) as pool:
        child_ok = list(pool.map(spawn_worker, range(6)))

    assert sum(1 for ok in child_ok if ok) == 2
    assert repo.get_budget_usage(task_spec.task_id).active_children == 2


@pytest.mark.n1
async def test_short_transaction_discipline_no_io_lock(tmp_path: Path) -> None:
    db_path = tmp_path / "short_tx.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    registry = ToolRegistry(clock=clock)
    tool_entered = threading.Event()
    writer_committed = threading.Event()
    writer_error: list[BaseException] = []

    spec = ToolSpec(
        tool_id="slow_read",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object", "required": ["ok"]},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="default_verifier",
    )

    def slow_handler(args: dict[str, object], ctx: ToolExecutionContext) -> dict[str, object]:
        del args, ctx
        tool_entered.set()
        # Wait for concurrent DB writer thread to commit while tool is executing
        assert writer_committed.wait(timeout=2.0), "DB remained locked during tool execution!"
        return {"ok": True}

    registry.register(spec, slow_handler)
    task_spec = _make_task("task-short-tx")
    task_spec = task_spec.model_copy(
        update={
            "scope": TaskScope(
                facility_id="plant-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=("slow_read",),
                read_only=True,
            )
        }
    )

    model = EmulatedModelClient(mode="happy_path")
    coord = Coordinator(repo, model, registry, clock=clock)
    run = coord.submit_task(task_spec)

    def concurrent_writer() -> None:
        try:
            assert tool_entered.wait(timeout=2.0)
            time.sleep(0.01)
            repo.append_audit_log(
                task_id=task_spec.task_id,
                run_id=run.run_id,
                actor="external_monitor",
                action="heartbeat_during_tool_io",
                decision="allow",
                detail={"ok": True},
            )
            writer_committed.set()
        except BaseException as exc:  # pragma: no cover
            writer_error.append(exc)

    thread = threading.Thread(target=concurrent_writer, daemon=True)
    thread.start()
    result = await coord.run_until_settled(run.run_id)
    thread.join(timeout=2.0)

    assert not writer_error
    assert writer_committed.is_set()
    assert result.status == TaskStatus.SUCCEEDED


@pytest.mark.n1
def test_camelcase_query_param_secrets_redacted_and_detected(tmp_path: Path) -> None:
    raw_url = (
        "https://scada.local/view?accessToken=tok1&sessionToken=tok2&refreshToken=tok3"
        "&authToken=tok4&clientSecret=sec1&csrfToken=csrf1&privateKey=pk1&apiKey=ak1"
    )
    assert contains_unredacted_secret_strict(raw_url) is True
    scrubbed = redact_string_strict(raw_url)
    assert contains_unredacted_secret_strict(scrubbed) is False
    for param in (
        "accessToken",
        "sessionToken",
        "refreshToken",
        "authToken",
        "clientSecret",
        "csrfToken",
        "privateKey",
        "apiKey",
    ):
        assert f"{param}=[REDACTED]" in scrubbed

    db_path = tmp_path / "camel_query_redaction.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()
    task_spec, run = repo.create_task_and_run(_make_task("t-camel-query"))
    step = repo.enqueue_step(run.run_id, "read_scada", {}, "v", EffectClass.READ)
    bad_rcpt = ActionReceipt(
        receipt_id="rcpt-camel-q",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args={},
        operation_key=step.operation_key,
        duration_ms=1.0,
        evidence_refs=("https://scada.local/alarms?accessToken=leak123",),
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    with pytest.raises(ValueError, match="unredacted secret"):
        repo.append_receipt(bad_rcpt)
