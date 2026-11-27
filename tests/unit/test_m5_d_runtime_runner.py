"""N1 unit tests for Milestone M5 Track D fixes (runtime area resolution & runner)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from src.adapters.config import AreaConfig, AssetMapping, FacilityConfig, load_facility_config
from src.contracts.enums import TaskStatus
from src.contracts.models import TaskSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolRegistry
from src.model import EmulatedModelClient, EmulatedTurn, ModelDecision, ModelUsage
from src.runtime import (
    _NON_AREA_APPROVAL_TOKENS,
    RuntimeCoordinatorAdapter,
    _resolve_area_from_human_input,
)
from src.storage.memory import MemoryAccessContext, MemoryStore
from src.storage.repo import StorageRepo
from src.web.live_browser import LiveBrowserController
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import WorkspaceStore


def _make_runner(
    tmp_path: Path,
    *,
    coordinator: Any | None = None,
    memory_store: Any | None = None,
) -> tuple[WorkspaceStore, EventBus, AgentTurnRunner, RuntimeCoordinatorAdapter | None]:
    store = WorkspaceStore(tmp_path / "ws.sqlite3")
    bus = EventBus()
    browser = LiveBrowserController(profile_root=tmp_path / "browser")
    adapter: RuntimeCoordinatorAdapter | None = None
    coord = coordinator
    if coord is None:
        repo = StorageRepo(tmp_path / "coord.sqlite3")
        repo.init_db()
        usage = ModelUsage(prompt_tokens=8, completion_tokens=8, total_tokens=16)
        client = EmulatedModelClient(
            mode="custom",
            default_turns=[
                EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="final",
                        final_answer="Routine runtime completed cleanly.",
                        usage=usage,
                    )
                )
            ]
            * 4,
        )
        raw_coord = Coordinator(repo=repo, tool_registry=ToolRegistry(), model_client=client)
        adapter = RuntimeCoordinatorAdapter(repo=repo, coordinator=raw_coord)
        coord = adapter

    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=coord,
        uploads_dir=tmp_path / "uploads",
        memory_store=memory_store,
    )
    return store, bus, runner, adapter


# ---------------------------------------------------------------------------
# D1: _resolve_area_from_human_input & _resume_and_stream_runtime_run payload
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_resolve_area_filters_approval_tokens_and_validates_choice() -> None:
    cfg = load_facility_config(Path("lab/configs/facility_a.json"))

    # All non-area approval tokens must be rejected (case-insensitively) on both area & choice
    for token in sorted(_NON_AREA_APPROVAL_TOKENS):
        assert _resolve_area_from_human_input({"choice": token}, cfg) is None
        assert _resolve_area_from_human_input({"choice": token.upper()}, cfg) is None
        assert _resolve_area_from_human_input({"area": token}, cfg) is None
        assert _resolve_area_from_human_input({"area": f" {token.title()} "}, cfg) is None

    # Choice must match known areas when config defines areas/assets
    assert _resolve_area_from_human_input({"choice": "area-1"}, cfg) == "area-1"
    assert _resolve_area_from_human_input({"choice": "area-99"}, cfg) is None

    # Out-of-scope explicit "area" is still returned so verifier scope check handles it
    assert _resolve_area_from_human_input({"area": "area-99"}, cfg) == "area-99"

    # Non-area choice falls through to valid choice or asset_id lookup
    assert _resolve_area_from_human_input({"area": "allow_once", "choice": "area-1"}, cfg) == (
        "area-1"
    )
    assert (
        _resolve_area_from_human_input({"choice": "allow_once", "asset_id": "bomba-34-a1"}, cfg)
        == "area-1"
    )

    # Empty known_areas falls back to accepting non-token choice
    empty_cfg = FacilityConfig(
        facility_id="fac-empty",
        facility_name="Empty",
        areas={},
        assets=(),
    )
    assert _resolve_area_from_human_input({"choice": "custom-zone"}, empty_cfg) == "custom-zone"
    assert _resolve_area_from_human_input({"choice": "allow_once"}, empty_cfg) is None

    # Assets with areas also populate known_areas even if config.areas is empty
    asset_only_cfg = FacilityConfig(
        facility_id="fac-asset",
        facility_name="Assets Only",
        areas={},
        assets=(
            AssetMapping(
                asset_id="p-1",
                area="zone-x",
                canonical_label="P-1",
            ),
        ),
    )
    assert _resolve_area_from_human_input({"choice": "zone-x"}, asset_only_cfg) == "zone-x"
    assert _resolve_area_from_human_input({"choice": "zone-y"}, asset_only_cfg) is None

    # Config with areas only
    area_only_cfg = FacilityConfig(
        facility_id="fac-area",
        facility_name="Areas Only",
        areas={"north": AreaConfig(display_name="North")},
        assets=(),
    )
    assert _resolve_area_from_human_input({"choice": "north"}, area_only_cfg) == "north"
    assert _resolve_area_from_human_input({"choice": "south"}, area_only_cfg) is None


@pytest.mark.n1
async def test_resume_and_stream_runtime_run_passes_approval_payload(tmp_path: Path) -> None:
    captured_resumes: list[tuple[str, dict[str, Any]]] = []

    class _StubSnapshotRun:
        status = TaskStatus.SUCCEEDED
        transition_reason = "completed"
        required_action = None
        progress = 1.0

    class _StubResult:
        answer = "Resumed OK"
        contradictions: tuple[str, ...] = ()
        partial_info: dict[str, Any] | None = None
        verified_observations: tuple[Any, ...] = ()

    class _StubSnapshot:
        run = _StubSnapshotRun()
        result = _StubResult()
        receipts: tuple[Any, ...] = ()
        transitions: tuple[Any, ...] = ()

    class _RecordingCoordinator:
        def submit_task(self, task: TaskSpec) -> Any:
            raise AssertionError(f"Unexpected submit_task: {task}")

        def get_task_snapshot(self, run_id: str) -> Any:
            del run_id
            return _StubSnapshot()

        def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Any:
            captured_resumes.append((run_id, dict(human_input)))
            return _StubSnapshotRun()

        def cancel_task(self, run_id: str, *, reason: str) -> Any:
            del run_id, reason
            return _StubSnapshotRun()

        async def wait_for_run(self, run_id: str, *, timeout: float | None = None) -> Any:
            del run_id, timeout
            return _StubSnapshot()

    store, _bus, runner, _ = _make_runner(tmp_path, coordinator=_RecordingCoordinator())
    try:
        bot = store.get_bot("bot_ops")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        appr = store.create_approval(
            bot_id="bot_ops",
            thread_id=thread_id,
            kind="standard",
            title="Re-auth SCADA",
            target="run:run_xyz",
            arguments={"run_id": "run_xyz"},
            pending_context={"run_id": "run_xyz", "bot_id": "bot_ops", "thread_id": thread_id},
        )
        resolved = store.resolve_approval(str(appr["id"]), "allow_once")
        await runner.on_approval_resolved(resolved, decision="allow_once")
        await runner.wait_for_active_turn(thread_id)

        assert captured_resumes == [
            (
                "run_xyz",
                {
                    "approval_decision": "allow_once",
                    "approved": True,
                    "reauthenticated": True,
                },
            )
        ]
        assert "choice" not in captured_resumes[0][1]
    finally:
        await runner.stop_scheduler()
        store.close()


# ---------------------------------------------------------------------------
# D2: Routines safety_floor + ask_first HITL pause/resume + attention sync
# ---------------------------------------------------------------------------


@pytest.mark.n1
async def test_routine_bg_blocks_safety_floor_violation(tmp_path: Path) -> None:
    store, bus, runner, adapter = _make_runner(tmp_path)
    try:
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Unsafe Shell Routine",
                "instruction": "Run rm -rf / on production host",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
        await runner._run_routine_bg(routine=routine, run=run)

        runs = store.list_routine_runs(str(routine["id"]))
        assert len(runs) == 1
        assert runs[0]["status"] == "failed"
        assert "safety_floor" in str(runs[0]["error"])
        assert runs[0]["finished_at"] is not None
        assert runner.policy_audit_log
        events = bus.recent_events(limit=20)
        assert any(
            ev["type"] == "routine.run.status"
            and ev["payload"]["run"]["status"] == "failed"
            for ev in events
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None
        assert bot["needs_attention"] is False
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
async def test_routine_ask_first_pause_and_allow_once_always_allow_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.replace_auto_review_rules(
            [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]
        )
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Deploy Release Routine",
                "instruction": "Deploy release to staging",
                "schedule_type": "webhook",
                "enabled": True,
            },
        )

        async def _fake_stream_agy(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {"type": "delta", "text": "Staging deployment completed."}
            yield {"type": "done", "response": "Staging deployment completed."}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_stream_agy)

        initial_run = await runner.execute_routine(str(routine["id"]), trigger="webhook")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)

        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        assert bot["status_state"] == "waiting_human"
        assert bot["needs_attention"] is True

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        appr = approvals[0]
        assert appr["kind"] == "ask_first"
        assert appr["allow_always_allowed"] is True
        pending_ctx = store.get_approval_pending_context(str(appr["id"]))
        assert pending_ctx is not None
        assert pending_ctx["routine_id"] == routine["id"]
        assert pending_ctx["routine_run_id"] == initial_run["id"]
        assert pending_ctx["trigger"] == "webhook"
        assert pending_ctx["skip_auto_review"] is True

        # Resolve with allow_once -> re-activates existing run with skip_auto_review=True
        resolved = store.resolve_approval(str(appr["id"]), "allow_once")
        await runner.on_approval_resolved(resolved, decision="allow_once")
        await runner.wait_for_active_turn(thread_id)
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.02)

        runs = store.list_routine_runs(str(routine["id"]))
        assert runs[0]["id"] == initial_run["id"]
        assert runs[0]["trigger"] == "webhook"
        assert runs[0]["status"] == "succeeded"
        assert isinstance(runs[0]["message_id"], str) and runs[0]["message_id"]
        # Must not create a second approval loop
        assert len(store.list_thread_approvals(thread_id)) == 1

        bot_after = store.get_bot("bot_chief")
        assert bot_after is not None
        assert bot_after["status_state"] == "idle"
        assert bot_after["needs_attention"] is False

        # Trigger again and resolve with always_allow -> adds allow_auto rule and runs
        run2 = await runner.execute_routine(str(routine["id"]), trigger="cron")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["id"] == run2["id"] and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)
        appr2 = store.list_thread_approvals(thread_id)[-1]
        resolved2 = store.resolve_approval(str(appr2["id"]), "always_allow")
        await runner.on_approval_resolved(
            resolved2, decision="always_allow", rule_text="Allow deploying release to staging"
        )
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["id"] == run2["id"] and cur[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.02)

        rules = store.list_auto_review_rules()
        assert any(r["bucket"] == "allow_auto" for r in rules)
        events = bus.recent_events(limit=50)
        assert any(
            ev["type"] == "routine.run.status"
            and ev["payload"]["run"]["id"] == initial_run["id"]
            and ev["payload"]["run"]["status"] == "waiting_approval"
            for ev in events
        )
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
@pytest.mark.parametrize("decision", ["deny", "skip"])
async def test_routine_ask_first_deny_and_skip_mark_run_failed(
    tmp_path: Path,
    decision: str,
) -> None:
    store, bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.replace_auto_review_rules(
            [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]
        )
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Deploy Release Routine",
                "instruction": "Deploy release to production",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run = await runner.execute_routine(str(routine["id"]), trigger="manual")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)

        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        appr = store.list_thread_approvals(thread_id)[0]
        resolved = store.resolve_approval(str(appr["id"]), decision)
        await runner.on_approval_resolved(resolved, decision=decision)
        await runner.wait_for_active_turn(thread_id)

        runs = store.list_routine_runs(str(routine["id"]))
        assert runs[0]["id"] == run["id"]
        assert runs[0]["status"] == "failed"
        expected_past = "denied" if decision == "deny" else "skipped"
        assert runs[0]["error"] == f"Routine paused for approval was {expected_past}."
        assert runs[0]["finished_at"] is not None

        bot_after = store.get_bot("bot_chief")
        assert bot_after is not None
        assert bot_after["status_state"] == "idle"
        assert bot_after["needs_attention"] is False

        events = bus.recent_events(limit=30)
        assert any(
            ev["type"] == "routine.run.status"
            and ev["payload"]["run"]["id"] == run["id"]
            and ev["payload"]["run"]["status"] == "failed"
            for ev in events
        )
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
def test_match_ask_first_rule_normalizes_inflections_and_skips_unrelated() -> None:
    from src.web.v1.runner import _match_ask_first_rule

    rules = [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]
    assert _match_ask_first_rule("Deploy release to staging", rules) == (
        "Ask before deploying release"
    )
    assert _match_ask_first_rule("Summarize quarterly weather outlook", rules) is None


@pytest.mark.n1
async def test_routine_approval_resume_when_routine_deleted_fails_gracefully(
    tmp_path: Path,
) -> None:
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.replace_auto_review_rules(
            [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]
        )
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Deleted Routine",
                "instruction": "Deploy release now",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run = await runner.execute_routine(str(routine["id"]), trigger="manual")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)

        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        appr = store.list_thread_approvals(thread_id)[0]
        store.delete_routine(str(routine["id"]))

        resolved = store.resolve_approval(str(appr["id"]), "allow_once")
        await runner.on_approval_resolved(resolved, decision="allow_once")
        await runner.wait_for_active_turn(thread_id)

        msgs, _ = store.list_thread_messages(thread_id)
        assert any("no longer exists" in str(m["content"]) for m in msgs)
        assert run["id"]  # verified initial run existed before deletion
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


# ---------------------------------------------------------------------------
# D3: _build_memory_section wired to real MemoryStore.build_context_injection
# ---------------------------------------------------------------------------


@pytest.mark.n1
async def test_build_memory_section_uses_memory_store_acl_and_ttl(tmp_path: Path) -> None:
    mem = MemoryStore(tmp_path / "mem.sqlite3")
    store, _bus, runner, adapter = _make_runner(tmp_path, memory_store=mem)
    try:
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        store.update_bot("bot_chief", {"project_name": "proj-alpha"})
        bot = store.get_bot("bot_chief")
        assert bot is not None

        # 1. Accessible user preference (pinned)
        mem.create_memory(
            scope="user",
            scope_id="operator",
            kind="preference",
            title="Unit Preference",
            content="Report pressures in bar and temperatures in Celsius.",
            actor_role="Operator",
            created_by="operator",
        )
        # 2. Cross-user private memory -> MUST be excluded by SQL ACL
        mem.create_memory(
            scope="user",
            scope_id="other_operator",
            kind="preference",
            title="Other User Secret",
            content="CONFIDENTIAL_OTHER_USER_NOTE",
            actor_role="Operator",
            created_by="other_operator",
        )
        # 3. Expired dated_observation -> MUST be excluded by TTL
        mem.create_memory(
            scope="agent_role",
            scope_id="bot_chief",
            kind="dated_observation",
            title="Expired Reading",
            content="STALE_EXPIRED_PUMP_VALUE",
            observed_at="2020-01-01T00:00:00Z",
            valid_until="2020-01-02T00:00:00Z",
            actor_role="Operator",
        )
        # 4. Active project_area memory -> included for proj-alpha, excluded for proj-beta
        mem.create_memory(
            scope="project_area",
            scope_id="proj-alpha",
            kind="dated_observation",
            title="Alpha Pump Baseline",
            content="Pump 34 vibration baseline is 1.8 mm/s.",
            observed_at="2026-11-26T00:00:00Z",
            valid_until="2099-01-01T00:00:00Z",
            actor_role="Operator",
        )
        # 5. Thread-scoped memory -> included in thread_id only
        mem.create_memory(
            scope="thread",
            scope_id=thread_id,
            kind="source_reference",
            title="OEM Manual Ref",
            content="Pump 34 manual section 4.2",
            actor_role="Operator",
        )

        prompt = runner._build_bot_prompt(
            bot=bot,
            thread_id=thread_id,
            user_message={"content": "Check Pump 34 vibration baseline and manual"},
            skill_ids=[],
            thinking_level="medium",
        )
        assert "Report pressures in bar and temperatures in Celsius." in prompt
        assert "Pump 34 vibration baseline is 1.8 mm/s." in prompt
        assert "Pump 34 manual section 4.2" in prompt
        assert "CONFIDENTIAL_OTHER_USER_NOTE" not in prompt
        assert "STALE_EXPIRED_PUMP_VALUE" not in prompt

        # Different project + different thread should exclude project_area and thread memories
        other_section = runner._build_memory_section(
            bot=bot,
            thread_id="thr_unrelated",
            query="Pump 34 vibration baseline manual",
            project_id="proj-beta",
        )
        assert other_section is not None
        assert "Report pressures in bar and temperatures in Celsius." in other_section
        assert "Pump 34 vibration baseline is 1.8 mm/s." not in other_section
        assert "Pump 34 manual section 4.2" not in other_section
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        mem.close()
        store.close()


@pytest.mark.n1
async def test_build_memory_section_search_memories_fallback_and_legacy(tmp_path: Path) -> None:
    class _EmptyInjectionWithSearchMemories:
        def build_context_injection(self, access_ctx: MemoryAccessContext, *, query: str) -> Any:
            del access_ctx, query

            class _EmptyBundle:
                combined_text = ""

            return _EmptyBundle()

        def search_memories(
            self, access_ctx: MemoryAccessContext, query: str, *, limit: int = 8
        ) -> list[dict[str, Any]]:
            del access_ctx, query, limit
            return [
                {
                    "kind": "dated_observation",
                    "observed_at": "2026-11-26T00:00:00Z",
                    "valid_until": "2099-01-01T00:00:00Z",
                    "title": "Fallback Hit",
                    "content": "Recovered from search_memories",
                }
            ]

    store, _bus, runner, adapter = _make_runner(
        tmp_path, memory_store=_EmptyInjectionWithSearchMemories()
    )
    try:
        bot = store.get_bot("bot_chief")
        assert bot is not None
        sec = runner._build_memory_section(
            bot=bot, thread_id=str(bot["thread_id"]), query="fallback"
        )
        assert sec is not None
        assert "Recovered from search_memories" in sec
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


# ---------------------------------------------------------------------------
# D4: Safety-floor metadata persistence via update_message + SSE
# ---------------------------------------------------------------------------


@pytest.mark.n1
async def test_safety_floor_persists_metadata_via_update_message_and_sse(tmp_path: Path) -> None:
    store, bus, runner, adapter = _make_runner(tmp_path)
    update_calls: list[tuple[str, dict[str, Any]]] = []
    orig_update_message = store.update_message

    def _spy_update_message(message_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        update_calls.append((message_id, dict(updates)))
        res = orig_update_message(message_id, updates)
        # Simulate M5-B store returning persisted metadata even when running against current store
        if "metadata" in updates and "metadata" not in res:
            res = {**res, "metadata": updates["metadata"]}
        return res

    store.update_message = _spy_update_message  # type: ignore[method-assign]

    try:
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        u_msg = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content="Please run rm -rf / --no-preserve-root right now",
        )
        runner.start_turn(thread_id=thread_id, user_message=u_msg)
        for _ in range(60):
            if update_calls:
                break
            await asyncio.sleep(0.02)

        assert len(update_calls) == 1
        msg_id, sent_updates = update_calls[0]
        assert "metadata" in sent_updates
        meta = sent_updates["metadata"]
        assert meta["verdict"] == "contradicted"
        assert "safety floor" in meta["degraded_banner"].lower()

        completed_events = [
            ev
            for ev in bus.recent_events(limit=20)
            if ev["type"] == "message.completed" and ev["payload"].get("message_id") == msg_id
        ]
        assert len(completed_events) == 1
        assert completed_events[0]["payload"]["message"]["metadata"] == meta
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


# ---------------------------------------------------------------------------
# D2 Iteration 2 Regressions: always_allow (rule_text=None), inflections, idle presence
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_match_ask_first_rule_handles_short_e_inflections_short_verbs_and_negatives() -> None:
    from src.web.v1.runner import _match_ask_first_rule, _normalize_rule_token, _rule_tokens

    positive_pairs = [
        ("Ask before modifying files", "Modify the file carefully"),
        ("Ask before updating rules", "Update rule immediately"),
        ("Ask before saving notes", "Save note in log"),
        ("Ask before wiping pages", "Wipe page content"),
        ("Ask before using shell", "Use shell to inspect logs"),
        ("Ask before running jobs", "Run daily jobs now"),
        ("Ask before going live", "Go live with changes"),
        ("Ask before doing cleanup", "Do cleanup of cache"),
        ("Ask before saving files", "Save files to archive"),
        ("Ask before putting secrets", "Put secret in vault"),
        ("Ask before setting flags", "Set flag on server"),
        ("Ask before getting tokens", "Get token from api"),
        ("Ask before adding entries", "Add entry to log"),
        ("Ask before deleting keys", "Del key? No, delete key now"),
    ]
    for rule_text, prompt in positive_pairs:
        rules = [{"bucket": "ask_first", "rule_text": rule_text}]
        assert _match_ask_first_rule(prompt, rules) == rule_text, (
            f"Expected match for rule={rule_text!r}, prompt={prompt!r}"
        )

    negative_pairs = [
        ("Ask before modifying files", "Read the files from disk"),
        ("Ask before saving notes", "List notes in folder"),
        ("Ask before saving notes", "Do not save anything"),
        ("Ask before using shell", "Tell us about shell"),
        (
            "Ask before deleting files or running destructive shell commands",
            "Run a check on files",
        ),
        (
            "Ask before deleting files or running destructive shell commands",
            "Run daily jobs now",
        ),
        ("Ask before running jobs", "Run diagnostics now"),
        ("Ask before going live", "Go home early"),
    ]
    for rule_text, prompt in negative_pairs:
        rules = [{"bucket": "ask_first", "rule_text": rule_text}]
        assert _match_ask_first_rule(prompt, rules) is None, (
            f"Unexpected false positive for rule={rule_text!r}, prompt={prompt!r}"
        )

    # Verify normalized stems match symmetrically
    assert _normalize_rule_token("file") == _normalize_rule_token("files")
    assert _normalize_rule_token("save") == _normalize_rule_token("saving")
    assert _normalize_rule_token("rule") == _normalize_rule_token("rules")
    assert _normalize_rule_token("note") == _normalize_rule_token("notes")
    assert _normalize_rule_token("wipe") == _normalize_rule_token("wiping")
    assert _normalize_rule_token("page") == _normalize_rule_token("pages")
    assert _normalize_rule_token("use") == _normalize_rule_token("using")
    assert _normalize_rule_token("run") == _normalize_rule_token("running")
    assert _normalize_rule_token("go") == _normalize_rule_token("going")
    assert _normalize_rule_token("do") == _normalize_rule_token("doing")
    for short_verb in ("use", "run", "go", "do", "rm", "put", "set", "get", "add", "del"):
        assert _rule_tokens(f"{short_verb} target"), f"Missing token for {short_verb!r}"


@pytest.mark.n1
async def test_routine_always_allow_without_rule_text_breaks_loop_and_resets_idle(
    tmp_path: Path,
) -> None:
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        # Use controlbot_runtime (no mock agy) to also exercise _await_runtime_run presence reset
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        store.replace_auto_review_rules(
            [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]
        )
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Deploy Release Routine",
                "instruction": "Deploy release to staging",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        run1 = await runner.execute_routine(str(routine["id"]), trigger="manual")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        assert approvals[0]["title"].startswith("Confirm routine:")

        # UI/API default: decision="always_allow" with rule_text=None
        resolved = store.resolve_approval(str(approvals[0]["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        for _ in range(100):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["id"] == run1["id"] and cur[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.02)

        runs = store.list_routine_runs(str(routine["id"]))
        assert runs[0]["id"] == run1["id"]
        assert runs[0]["status"] == "succeeded"

        bot_after_r1 = store.get_bot("bot_chief")
        assert bot_after_r1 is not None
        assert bot_after_r1["status_state"] == "idle"
        assert bot_after_r1["needs_attention"] is False

        # Run 2 MUST complete without pausing or creating a second approval
        run2 = await runner.execute_routine(str(routine["id"]), trigger="manual")
        for _ in range(100):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["id"] == run2["id"] and cur[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.02)

        runs_after = store.list_routine_runs(str(routine["id"]))
        assert runs_after[0]["id"] == run2["id"]
        assert runs_after[0]["status"] == "succeeded"
        assert len(store.list_thread_approvals(thread_id)) == 1

        bot_after_r2 = store.get_bot("bot_chief")
        assert bot_after_r2 is not None
        assert bot_after_r2["status_state"] == "idle"
        assert bot_after_r2["needs_attention"] is False
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
@pytest.mark.parametrize(
    ("ask_rule", "prompt"),
    [
        ("Ask before deploying release", "Deploy release to staging"),
        (
            "Ask before deleting files or running destructive shell commands",
            "Please delete files in temp workspace",
        ),
        (
            "Ask before deleting files or running destructive shell commands",
            "Please run rm -rf ./scratch_dir",
        ),
    ],
)
async def test_thread_turn_always_allow_without_rule_text_prevents_loop(
    tmp_path: Path,
    ask_rule: str,
    prompt: str,
) -> None:
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        store.replace_auto_review_rules([{"bucket": "ask_first", "rule_text": ask_rule}])
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        u1 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content=prompt,
        )
        runner.start_turn(thread_id=thread_id, user_message=u1)
        for _ in range(60):
            if store.list_thread_approvals(thread_id):
                break
            await asyncio.sleep(0.02)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        assert approvals[0]["kind"] == "ask_first"

        resolved = store.resolve_approval(str(approvals[0]["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        for _ in range(100):
            msgs, _ = store.list_thread_messages(thread_id)
            bot_msgs = [m for m in msgs if m["sender_type"] == "bot" and m["status"] == "done"]
            if bot_msgs:
                break
            await asyncio.sleep(0.02)
        msgs, _ = store.list_thread_messages(thread_id)
        assert any(m["sender_type"] == "bot" and m["status"] == "done" for m in msgs)

        # Turn 2 with matching prompt MUST NOT create a second approval
        u2 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content=prompt,
        )
        runner.start_turn(thread_id=thread_id, user_message=u2)
        for _ in range(100):
            msgs2, _ = store.list_thread_messages(thread_id)
            done_bots = [m for m in msgs2 if m["sender_type"] == "bot" and m["status"] == "done"]
            if len(done_bots) >= 2:
                break
            await asyncio.sleep(0.02)

        msgs2, _ = store.list_thread_messages(thread_id)
        assert len([m for m in msgs2 if m["sender_type"] == "bot" and m["status"] == "done"]) >= 2
        assert len(store.list_thread_approvals(thread_id)) == 1
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
async def test_routine_bg_terminal_error_and_safety_floor_reset_working_bot_to_idle(
    tmp_path: Path,
) -> None:
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})

        # 1. Runtime error exit (app_runtime disabled) after bot was "working" -> idle
        store.update_bot("bot_chief", {"status_state": "working", "status_subtext": "Busy"})
        store.update_connected_app("app_runtime", enabled=False)
        rtn_err = store.create_routine(
            "bot_chief",
            {
                "name": "Disabled Runtime Routine",
                "instruction": "Check pump pressure",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run_err = store.create_routine_run(str(rtn_err["id"]), "bot_chief", trigger="manual")
        await runner._run_routine_bg(routine=rtn_err, run=run_err)

        runs_err = store.list_routine_runs(str(rtn_err["id"]))
        assert runs_err[0]["status"] == "failed"
        bot_err = store.get_bot("bot_chief")
        assert bot_err is not None
        assert bot_err["status_state"] == "idle"
        assert bot_err["needs_attention"] is False

        # 2. Safety floor fail after bot was "working" -> idle
        store.update_bot("bot_chief", {"status_state": "working", "status_subtext": "Busy"})
        rtn_sf = store.create_routine(
            "bot_chief",
            {
                "name": "Safety Floor Routine",
                "instruction": "Run rm -rf / right now",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run_sf = store.create_routine_run(str(rtn_sf["id"]), "bot_chief", trigger="manual")
        await runner._run_routine_bg(routine=rtn_sf, run=run_sf)

        runs_sf = store.list_routine_runs(str(rtn_sf["id"]))
        assert runs_sf[0]["status"] == "failed"
        bot_sf = store.get_bot("bot_chief")
        assert bot_sf is not None
        assert bot_sf["status_state"] == "idle"
        assert bot_sf["needs_attention"] is False
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


# ---------------------------------------------------------------------------
# D2 Iteration 3 Regressions: exact allow_auto scoping, >120/1000-char prompts, WFI routine
# ---------------------------------------------------------------------------


@pytest.mark.n1
@pytest.mark.parametrize(
    ("approved_prompt", "must_still_block"),
    [
        (
            "Please delete temp files in workspace",
            [
                "Delete temp files in production database",
                "Delete temp files in /etc/passwd",
            ],
        ),
        (
            "Please run rm -rf",
            [
                "Please run rm -rf ./prod",
                "Run rm -rf /var/log",
            ],
        ),
        (
            (
                "please confirm our routine action before all these things can just be about "
                "your own " * 2
            )[:125]
            + " delete files now",
            [
                (
                    "please confirm our routine action before all these things can just be about "
                    "your own " * 2
                )[:125]
                + " run rm -rf ./prod",
            ],
        ),
        (
            (
                "please confirm our routine action before all these things can just be about "
                "your own " * 14
            )
            + " delete files now",
            [
                (
                    "please confirm our routine action before all these things can just be about "
                    "your own " * 14
                )
                + " run rm -rf ./prod",
            ],
        ),
    ],
)
async def test_always_allow_exact_scoping_blocks_escalation_and_truncation_loops(
    tmp_path: Path,
    approved_prompt: str,
    must_still_block: list[str],
) -> None:
    from src.web.v1.runner import _match_ask_first_rule

    seeded_rule = "Ask before deleting files or running destructive shell commands"
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        store.replace_auto_review_rules([{"bucket": "ask_first", "rule_text": seeded_rule}])
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        u1 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content=approved_prompt,
        )
        runner.start_turn(thread_id=thread_id, user_message=u1)
        for _ in range(60):
            if store.list_thread_approvals(thread_id):
                break
            await asyncio.sleep(0.02)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        resolved = store.resolve_approval(str(approvals[0]["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        for _ in range(100):
            msgs, _ = store.list_thread_messages(thread_id)
            if any(m["sender_type"] == "bot" and m["status"] == "done" for m in msgs):
                break
            await asyncio.sleep(0.02)

        rules = store.list_auto_review_rules()
        allow_rules = [r for r in rules if r["bucket"] == "allow_auto"]
        assert len(allow_rules) == 1
        assert allow_rules[0]["rule_text"].startswith(("Allow exact: ", "Allow exact-sha256: "))

        # Identical prompt on Turn 2 MUST be allowed (no infinite approval loop)
        assert _match_ask_first_rule(approved_prompt, rules) is None

        # Escalated/prefix-sharing variants MUST STILL trigger ask_first
        for blocked_prompt in must_still_block:
            assert _match_ask_first_rule(blocked_prompt, rules) == seeded_rule, (
                f"Bypass detected for {blocked_prompt!r} after approving {approved_prompt!r}"
            )
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
def test_quoted_allow_auto_rule_does_not_fall_through_to_bag_of_words() -> None:
    from src.web.v1.runner import _match_ask_first_rule

    seeded_rule = "Ask before deleting files or running destructive shell commands"
    rules = [
        {"bucket": "allow_auto", "rule_text": 'Allow: "delete temp files in workspace"'},
        {"bucket": "ask_first", "rule_text": seeded_rule},
    ]
    assert _match_ask_first_rule("Please delete temp files in workspace", rules) is None
    assert _match_ask_first_rule("Delete temp files in production database", rules) == seeded_rule
    assert _match_ask_first_rule("Delete temp files in /etc/passwd", rules) == seeded_rule


@pytest.mark.n1
async def test_routine_bg_waiting_for_input_marks_waiting_approval_and_preserves_presence(
    tmp_path: Path,
) -> None:
    from datetime import timedelta

    from src.contracts.budgets import BudgetConfig
    from src.contracts.common import utc_now
    from src.contracts.models import Run, TaskScope
    from src.web.protocols import TaskSnapshot

    class _WfiCoordinator:
        def __init__(self) -> None:
            self._spec: TaskSpec | None = None

        async def submit_task(self, spec: TaskSpec) -> Run:
            self._spec = spec
            now = utc_now()
            return Run(
                run_id="run_wfi_rtn",
                task_id=spec.task_id,
                status=TaskStatus.WAITING_FOR_INPUT,
                required_action="Re-authenticate SCADA session",
                deadline_at=now + timedelta(minutes=5),
                created_at=now,
                updated_at=now,
            )

        async def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
            now = utc_now()
            spec = self._spec or TaskSpec(
                task_id="task_wfi_rtn",
                user_id="operator",
                profile_id="default",
                scope=TaskScope(facility_id="facility-a", read_only=True),
                query="Check SCADA alarms",
            )
            return TaskSnapshot(
                run=Run(
                    run_id=run_id,
                    task_id=spec.task_id,
                    status=TaskStatus.WAITING_FOR_INPUT,
                    required_action="Re-authenticate SCADA session",
                    deadline_at=now + timedelta(minutes=5),
                    created_at=now,
                    updated_at=now,
                ),
                task=spec,
                budget_config=BudgetConfig(),
            )

        async def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Any:
            del run_id, human_input
            return None

        async def cancel_task(self, run_id: str, reason: str | None = None) -> Any:
            del run_id, reason
            return None

        async def subscribe_events(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
            del run_id
            if False:
                yield {}

    store, bus, runner, _ = _make_runner(tmp_path, coordinator=_WfiCoordinator())
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        rtn = store.create_routine(
            "bot_chief",
            {
                "name": "WFI Routine",
                "instruction": "Check SCADA alarms",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run = store.create_routine_run(str(rtn["id"]), "bot_chief", trigger="manual")
        await runner._run_routine_bg(routine=rtn, run=run)

        runs = store.list_routine_runs(str(rtn["id"]))
        assert runs[0]["status"] == "waiting_approval"
        assert "paused for operator input" in str(runs[0]["summary"])

        bot = store.get_bot("bot_chief")
        assert bot is not None
        assert bot["status_state"] == "waiting_human"
        assert bot["needs_attention"] is True

        assert any(
            ev["type"] == "routine.run.status"
            and ev["payload"]["run"]["status"] == "waiting_approval"
            for ev in bus.recent_events(limit=20)
        )
    finally:
        await runner.stop_scheduler()
        store.close()


@pytest.mark.n1
async def test_routine_long_instruction_always_allow_exact_avoids_truncation_loop(
    tmp_path: Path,
) -> None:
    from src.web.v1.runner import _match_ask_first_rule

    long_instr = (
        ("please confirm our routine action before all these things " * 11)[:560]
        + " delete files now"
    )
    seeded_rule = "Ask before deleting files or running destructive shell commands"
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        store.replace_auto_review_rules([{"bucket": "ask_first", "rule_text": seeded_rule}])
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Long Stopword Routine",
                "instruction": long_instr,
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        run1 = await runner.execute_routine(str(routine["id"]), trigger="manual")
        for _ in range(50):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["status"] == "waiting_approval":
                break
            await asyncio.sleep(0.02)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        resolved = store.resolve_approval(str(approvals[0]["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        for _ in range(100):
            cur = store.list_routine_runs(str(routine["id"]))
            if cur and cur[0]["id"] == run1["id"] and cur[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.02)

        rules = store.list_auto_review_rules()
        assert _match_ask_first_rule(long_instr, rules) is None
        assert _match_ask_first_rule(long_instr[:560] + " run rm -rf ./prod", rules) == seeded_rule
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


# ---------------------------------------------------------------------------
# D2 Iteration 4 Regressions: no Allow:<matched_rule> escalation, quote regex,
# and WAITING_FOR_INPUT routine lifecycle completion
# ---------------------------------------------------------------------------


@pytest.mark.n1
@pytest.mark.parametrize(
    ("ask_rules", "approved_prompt", "must_still_block", "expected_match"),
    [
        (
            ["Ask before deleting files"],
            "Please delete temp files in workspace",
            ["Delete all files in production database"],
            "Ask before deleting files",
        ),
        (
            ["Ask before deleting files or running destructive shell commands"],
            "Delete destructive shell files in /tmp/scratch",
            ["Delete destructive shell files in /etc/passwd"],
            "Ask before deleting files or running destructive shell commands",
        ),
        (
            [
                "Ask before deploying release",
                "Ask before deleting files or running destructive shell commands",
            ],
            "Deploy release to staging",
            ["Deploy release and delete production database"],
            "Ask before deleting files or running destructive shell commands",
        ),
    ],
)
async def test_always_allow_never_synthesizes_rule_wide_bypass_when_prompt_present(
    tmp_path: Path,
    ask_rules: list[str],
    approved_prompt: str,
    must_still_block: list[str],
    expected_match: str,
) -> None:
    from src.web.v1.runner import _match_ask_first_rule

    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        store.replace_auto_review_rules(
            [{"bucket": "ask_first", "rule_text": r} for r in ask_rules]
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        u1 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content=approved_prompt,
        )
        runner.start_turn(thread_id=thread_id, user_message=u1)
        for _ in range(60):
            if store.list_thread_approvals(thread_id):
                break
            await asyncio.sleep(0.02)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        resolved = store.resolve_approval(str(approvals[0]["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        for _ in range(100):
            msgs, _ = store.list_thread_messages(thread_id)
            if any(m["sender_type"] == "bot" and m["status"] == "done" for m in msgs):
                break
            await asyncio.sleep(0.02)

        rules = store.list_auto_review_rules()
        allow_rules = [r for r in rules if r["bucket"] == "allow_auto"]
        assert len(allow_rules) == 1
        assert allow_rules[0]["rule_text"].startswith(("Allow exact: ", "Allow exact-sha256: "))
        assert not allow_rules[0]["rule_text"].startswith("Allow: ")

        assert _match_ask_first_rule(approved_prompt, rules) is None
        for blocked_prompt in must_still_block:
            matched = _match_ask_first_rule(blocked_prompt, rules)
            assert matched is not None and matched in set(ask_rules)
            # Also verify the specific target rule itself is NOT suppressed by allow_auto
            allow_only = [r for r in rules if r["bucket"] == "allow_auto"]
            assert (
                _match_ask_first_rule(
                    blocked_prompt,
                    allow_only + [{"bucket": "ask_first", "rule_text": expected_match}],
                )
                == expected_match
            )
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
async def test_always_allow_falls_back_to_matched_rule_only_when_prompt_empty(
    tmp_path: Path,
) -> None:
    store, _bus, runner, adapter = _make_runner(tmp_path)
    try:
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        appr = store.create_approval(
            bot_id="bot_chief",
            thread_id=thread_id,
            kind="ask_first",
            title="Confirm action",
            target="action",
            arguments={"matched_rule": "Ask before deploying release"},
            allow_always_allowed=True,
        )
        resolved = store.resolve_approval(str(appr["id"]), "always_allow")
        await runner.on_approval_resolved(resolved, decision="always_allow", rule_text=None)

        allow_rules = [
            r for r in store.list_auto_review_rules() if r["bucket"] == "allow_auto"
        ]
        assert [r["rule_text"] for r in allow_rules] == ["Allow: Ask before deploying release"]
    finally:
        await runner.stop_scheduler()
        if adapter is not None:
            await adapter.shutdown()
        store.close()


@pytest.mark.n1
def test_quoted_allow_auto_regex_requires_matching_quote_characters() -> None:
    from src.web.v1.runner import _match_ask_first_rule

    ask_rule = "Ask before deploying to production"
    # Mismatched embedded apostrophe inside double quotes must NOT extract bare "deploy"
    rules_double = [
        {"bucket": "allow_auto", "rule_text": 'Allow: "deploy\'s"'},
        {"bucket": "ask_first", "rule_text": ask_rule},
    ]
    assert _match_ask_first_rule("deploy to production", rules_double) == ask_rule
    assert _match_ask_first_rule("deploy's staging build", rules_double) is None

    # Mismatched embedded double-quote inside single quotes must NOT extract bare "deploy"
    rules_single = [
        {"bucket": "allow_auto", "rule_text": "Allow: 'deploy\"s'"},
        {"bucket": "ask_first", "rule_text": ask_rule},
    ]
    assert _match_ask_first_rule("deploy to production", rules_single) == ask_rule


@pytest.mark.n1
@pytest.mark.parametrize("decision", ["allow_once", "deny"])
async def test_routine_wfi_approval_resolution_updates_routine_run_status(
    tmp_path: Path,
    decision: str,
) -> None:
    from datetime import timedelta

    from src.contracts.budgets import BudgetConfig
    from src.contracts.common import utc_now
    from src.contracts.models import Result, Run, TaskScope
    from src.web.protocols import TaskSnapshot

    class _WfiLifecycleCoordinator:
        def __init__(self) -> None:
            self.submitted = 0
            self.resumed: list[tuple[str, dict[str, Any]]] = []
            self.cancelled: list[tuple[str, str | None]] = []
            self._status = TaskStatus.WAITING_FOR_INPUT
            self._spec: TaskSpec | None = None

        async def submit_task(self, spec: TaskSpec) -> Run:
            self.submitted += 1
            self._spec = spec
            now = utc_now()
            return Run(
                run_id="run_wfi_lifecycle",
                task_id=spec.task_id,
                status=self._status,
                required_action="Re-authenticate SCADA session",
                deadline_at=now + timedelta(minutes=5),
                created_at=now,
                updated_at=now,
            )

        async def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
            now = utc_now()
            spec = self._spec or TaskSpec(
                task_id="task_wfi_lifecycle",
                user_id="operator",
                profile_id="default",
                scope=TaskScope(facility_id="facility-a", read_only=True),
                query="Check SCADA alarms",
            )
            result = (
                Result(
                    task_id=spec.task_id,
                    run_id=run_id,
                    status=TaskStatus.SUCCEEDED,
                    answer="SCADA alarm check succeeded after re-auth.",
                )
                if self._status == TaskStatus.SUCCEEDED
                else None
            )
            return TaskSnapshot(
                run=Run(
                    run_id=run_id,
                    task_id=spec.task_id,
                    status=self._status,
                    required_action=(
                        "Re-authenticate SCADA session"
                        if self._status == TaskStatus.WAITING_FOR_INPUT
                        else None
                    ),
                    transition_reason=(
                        "completed"
                        if self._status == TaskStatus.SUCCEEDED
                        else "waiting_for_input"
                    ),
                    deadline_at=now + timedelta(minutes=5),
                    created_at=now,
                    updated_at=now,
                ),
                task=spec,
                budget_config=BudgetConfig(),
                result=result,
            )

        async def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Any:
            self.resumed.append((run_id, dict(human_input)))
            self._status = TaskStatus.SUCCEEDED
            return None

        async def cancel_task(self, run_id: str, reason: str | None = None) -> Any:
            self.cancelled.append((run_id, reason))
            self._status = TaskStatus.CANCELLED
            return None

        async def subscribe_events(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
            del run_id
            if False:
                yield {}

    coord = _WfiLifecycleCoordinator()
    store, bus, runner, _ = _make_runner(tmp_path, coordinator=coord)
    try:
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        rtn = store.create_routine(
            "bot_chief",
            {
                "name": "WFI Lifecycle Routine",
                "instruction": "Check SCADA alarms",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        run = store.create_routine_run(str(rtn["id"]), "bot_chief", trigger="manual")
        await runner._run_routine_bg(routine=rtn, run=run)

        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        appr = approvals[0]
        pending_ctx = store.get_approval_pending_context(str(appr["id"]))
        assert pending_ctx is not None
        assert pending_ctx["run_id"] == "run_wfi_lifecycle"
        assert pending_ctx["routine_id"] == rtn["id"]
        assert pending_ctx["routine_run_id"] == run["id"]

        resolved = store.resolve_approval(str(appr["id"]), decision)
        await runner.on_approval_resolved(resolved, decision=decision)
        await runner.wait_for_active_turn(thread_id)

        runs = store.list_routine_runs(str(rtn["id"]))
        assert runs[0]["id"] == run["id"]
        if decision == "allow_once":
            assert coord.submitted == 1  # resumed existing run, did NOT re-submit
            assert len(coord.resumed) == 1
            assert runs[0]["status"] == "succeeded"
            assert "SCADA alarm check succeeded" in str(runs[0]["summary"])
            assert runs[0]["finished_at"] is not None
            statuses = [
                ev["payload"]["run"]["status"]
                for ev in bus.recent_events(limit=30)
                if ev["type"] == "routine.run.status"
                and ev["payload"]["run"]["id"] == run["id"]
            ]
            assert "waiting_approval" in statuses
            assert "running" in statuses
            assert "succeeded" in statuses
        else:
            assert len(coord.cancelled) == 1
            assert runs[0]["status"] == "failed"
            assert runs[0]["finished_at"] is not None
            assert any(
                ev["type"] == "routine.run.status"
                and ev["payload"]["run"]["id"] == run["id"]
                and ev["payload"]["run"]["status"] == "failed"
                for ev in bus.recent_events(limit=30)
            )

        bot_after = store.get_bot("bot_chief")
        assert bot_after is not None
        assert bot_after["status_state"] == "idle"
        assert bot_after["needs_attention"] is False
    finally:
        await runner.stop_scheduler()
        store.close()
