"""N2 real Playwright + real HTTP integration tests for SessionManager, adapters, & Verifier."""

from __future__ import annotations

import asyncio
import json
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters import (
    AdapterPermissionError,
    EffectSimAdapter,
    MaintenanceAdapter,
    MappingCredentialProvider,
    OriginNotAllowedError,
    ScadaAdapter,
    SessionBusyError,
    SessionManager,
    SessionOwnershipError,
    SessionTakenOverError,
    SourceUnavailableError,
    TakeoverStateError,
    Verifier,
    load_facility_config,
    run_pump34_flow,
)
from src.contracts.enums import DataQuality, ReceiptOutcome, TaskStatus
from src.contracts.models import Observation, TaskScope, TaskSpec
from src.contracts.redaction import REDACTED_PLACEHOLDER, contains_unredacted_secret

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")


def _make_task(
    *,
    user_id: str,
    profile_id: str,
    allowed_origins: tuple[str, ...],
    read_only: bool = True,
    allowed_tools: tuple[str, ...] = (),
) -> TaskSpec:
    return TaskSpec(
        task_id=f"task-{user_id}-{profile_id}",
        user_id=user_id,
        profile_id=profile_id,
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=allowed_origins,
            allowed_areas=(),
            allowed_tools=allowed_tools,
            read_only=read_only,
        ),
        query="Check bomba 34 alarms, readings, and latest maintenance intervention",
    )


@pytest.mark.n2
async def test_playwright_session_isolation_persistence_and_ownership(tmp_path: Path) -> None:
    scada_app = create_scada_app(fixture_mode="ambiguity")
    async with run_asgi_server(scada_app) as scada_origin:
        config = load_facility_config(_FACILITY_A_PATH, {"scada": scada_origin})
        creds = MappingCredentialProvider(
            {
                ("operator_a1", "prof_a", "scada"): ("operator_a1", "scada-pass-a1"),
                ("operator_a2", "prof_b", "scada"): ("operator_a2", "scada-pass-a2"),
            }
        )
        profile_root = tmp_path / "profiles"

        async with SessionManager(profile_root, headless=True) as mgr:
            adapter = ScadaAdapter(mgr, creds)
            task_a = _make_task(
                user_id="operator_a1",
                profile_id="prof_a",
                allowed_origins=(scada_origin,),
            )
            task_b = _make_task(
                user_id="operator_a2",
                profile_id="prof_b",
                allowed_origins=(scada_origin,),
            )

            # Run two concurrent isolated sessions
            (obs_a, _), (obs_b, _) = await asyncio.gather(
                adapter.read_alarms(task=task_a, config=config, run_id="r-a"),
                adapter.read_alarms(task=task_b, config=config, run_id="r-b"),
            )
            assert obs_a[0].metadata["authenticated_user"] == "operator_a1"
            assert obs_a[0].area == "area-1"
            assert obs_b[0].metadata["authenticated_user"] == "operator_a2"
            assert obs_b[0].area == "area-2"

            # Verify OS profile dir 0o700 and session_meta.json 0o600
            dir_a = profile_root / "operator_a1" / "prof_a" / "scada"
            dir_b = profile_root / "operator_a2" / "prof_b" / "scada"
            assert stat.S_IMODE(dir_a.stat().st_mode) == 0o700
            assert stat.S_IMODE(dir_b.stat().st_mode) == 0o700
            assert stat.S_IMODE((dir_a / "session_meta.json").stat().st_mode) == 0o600

            sess_a = await mgr.open_session("operator_a1", "prof_a", "scada", (scada_origin,))
            ls_user = await sess_a.page.evaluate("window.localStorage.getItem('scada_user')")
            assert ls_user == "operator_a1"

        # Restart SessionManager WITHOUT credentials: persistent cookies keep session logged in!
        async with SessionManager(profile_root, headless=True) as mgr2:
            adapter2 = ScadaAdapter(mgr2, credential_provider=None)
            obs_a2, rcpt_a2 = await adapter2.read_alarms(
                task=task_a,
                config=config,
                run_id="r-a-reopen",
            )
            assert obs_a2[0].metadata["authenticated_user"] == "operator_a1"
            assert obs_a2[0].metadata["did_login"] is False
            assert rcpt_a2.outcome == ReceiptOutcome.SUCCEEDED

            # Ownership mismatch on existing profile_dir must fail closed across reopen
            meta_file = profile_root / "operator_a1" / "prof_a" / "scada" / "session_meta.json"
            tampered = json.loads(meta_file.read_text(encoding="utf-8"))
            tampered["user_id"] = "other_user"
            meta_file.write_text(json.dumps(tampered), encoding="utf-8")
            with pytest.raises(SessionOwnershipError):
                await mgr2.open_session("operator_a1", "prof_a", "scada", (scada_origin,))

        async with SessionManager(profile_root, headless=True) as mgr3:
            with pytest.raises(SessionOwnershipError):
                await mgr3.open_session("operator_a1", "prof_a", "scada", (scada_origin,))


@pytest.mark.n2
async def test_origin_allowlist_blocks_navigation_and_subresources(tmp_path: Path) -> None:
    scada_app = create_scada_app(fixture_mode="default")
    other_app = create_maintenance_app(fixture_mode="default")

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(other_app) as other_origin,
        SessionManager(tmp_path / "profiles", headless=True) as mgr,
    ):
        sess = await mgr.open_session("operator_a1", "p1", "scada", (scada_origin,))

        # Direct disallowed navigation rejected outside LLM
        with pytest.raises(OriginNotAllowedError):
            await mgr.navigate(sess.session_id, f"{other_origin}/login")

        # Subresource fetch from an allowed page to disallowed origin is aborted by route guard
        await mgr.navigate(sess.session_id, f"{scada_origin}/login")
        fetch_result = await sess.page.evaluate(
            """async (url) => {
                try {
                    await fetch(url);
                    return 'unexpected_ok';
                } catch (e) {
                    return 'blocked';
                }
            }""",
            f"{other_origin}/health",
        )
        assert fetch_result == "blocked"
        state = await mgr.get_session_state(sess.session_id)
        assert state is not None
        assert other_origin in state.blocked_origins


@pytest.mark.n2
async def test_human_takeover_mutual_exclusion_and_release(tmp_path: Path) -> None:
    scada_app = create_scada_app(fixture_mode="default")
    async with (
        run_asgi_server(scada_app) as scada_origin,
        SessionManager(tmp_path / "profiles", headless=True) as mgr,
    ):
        sess = await mgr.open_session("operator_a1", "p1", "scada", (scada_origin,))

        # Active lease blocks takeover
        async with mgr.acquire_lease(sess.session_id):
            with pytest.raises(SessionBusyError):
                await mgr.request_takeover(sess.session_id, owner="alice")

        # Idle takeover succeeds and blocks automation
        locked_state = await mgr.request_takeover(sess.session_id, owner="alice", reason="2fa")
        assert locked_state.takeover_active is True
        with pytest.raises(SessionTakenOverError):
            async with mgr.acquire_lease(sess.session_id):
                pass

        # Wrong owner cannot release
        with pytest.raises(TakeoverStateError):
            await mgr.release_takeover(sess.session_id, owner="bob")

        # Owner releases and automation resumes cleanly
        released = await mgr.release_takeover(sess.session_id, owner="alice")
        assert released.takeover_active is False
        async with mgr.acquire_lease(sess.session_id) as leased:
            assert leased.session_id == sess.session_id


@pytest.mark.n2
async def test_pump34_flow_a01_a02_a03_a04_a10_a12_a13(tmp_path: Path) -> None:
    ref_time = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    creds = MappingCredentialProvider(
        {
            ("operator_ro", "prof", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "prof", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
        SessionManager(tmp_path / "profiles", headless=True) as mgr,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        task = _make_task(
            user_id="operator_ro",
            profile_id="prof",
            allowed_origins=(scada_origin, maint_origin),
        )

        # A01: Default Pump 34 cross-source success
        res_a01, rcpts_a01 = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a01",
            reference_time=ref_time,
        )
        assert res_a01.status == TaskStatus.SUCCEEDED
        assert "ALM-3401" in res_a01.answer
        assert "WO-3408" in res_a01.answer
        assert len(rcpts_a01) == 3
        assert all(not contains_unredacted_secret(r.model_dump()) for r in rcpts_a01)

        # A12: Reordered HTML columns with zero code edits -> identical extracted observations
        scada_app.state.scada_state.set_mode("reordered")
        maint_app.state.maintenance_state.set_mode("reordered")
        res_a12, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a12",
            reference_time=ref_time,
        )
        assert res_a12.status == TaskStatus.SUCCEEDED
        assert "ALM-3401" in res_a12.answer
        assert "WO-3408" in res_a12.answer

        # A03: Stale / bad quality / out-of-window filtering
        scada_app.state.scada_state.set_mode("stale")
        maint_app.state.maintenance_state.set_mode("stale")
        res_a03, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a03",
            window_start=ref_time - timedelta(hours=2),
            window_end=ref_time,
            reference_time=ref_time,
        )
        assert res_a03.status == TaskStatus.SUCCEEDED
        assert "ALM-3405" in res_a03.answer
        assert "First authorized alarm [ALM-OLD-01]" not in res_a03.answer
        by_id = {o.metadata.get("record_id"): o for o in res_a03.verified_observations}
        assert by_id["ALM-OLD-01"].authorized_evidence is False
        assert by_id["RDG-STALE-01"].quality == DataQuality.STALE
        assert by_id["RDG-STALE-01"].authorized_evidence is False
        assert by_id["RDG-BAD-01"].quality == DataQuality.BAD
        assert by_id["RDG-BAD-01"].authorized_evidence is False
        assert by_id["ALM-3405"].authorized_evidence is True

        # A02: Multi-area ambiguity pauses with WAITING_FOR_INPUT
        scada_app.state.scada_state.set_mode("ambiguity")
        maint_app.state.maintenance_state.set_mode("ambiguity")
        res_a02, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a02",
            reference_time=ref_time,
        )
        assert res_a02.status == TaskStatus.WAITING_FOR_INPUT
        assert res_a02.required_action is not None
        assert "area-1" in res_a02.required_action
        assert "area-2" in res_a02.required_action

        # A13: Contradictory claims preserved without silent merge -> PARTIAL
        scada_app.state.scada_state.set_mode("contradictory")
        maint_app.state.maintenance_state.set_mode("contradictory")
        res_a13, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a13",
            reference_time=ref_time,
        )
        assert res_a13.status == TaskStatus.PARTIAL
        assert len(res_a13.contradictions) >= 1
        assert all(c.unresolved for c in res_a13.contradictions)

        # A04: SCADA down (503) while Maintenance healthy -> PARTIAL
        scada_app.state.scada_state.set_mode("down")
        maint_app.state.maintenance_state.set_mode("default")
        res_a04, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a04",
            reference_time=ref_time,
        )
        assert res_a04.status == TaskStatus.PARTIAL
        assert res_a04.partial_info is not None
        assert "scada" in res_a04.partial_info["missing_sources"]
        assert "maintenance" in res_a04.partial_info["available_sources"]

        # A10: Auth expired mid-session -> WAITING_FOR_INPUT
        scada_app.state.scada_state.set_mode("default")
        scada_app.state.scada_state.expire_all_sessions()
        res_a10, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-a10",
            reference_time=ref_time,
        )
        assert res_a10.status == TaskStatus.WAITING_FOR_INPUT
        assert res_a10.required_action is not None
        assert "scada" in res_a10.required_action.lower()


@pytest.mark.n2
async def test_effect_sim_adapter_reconciles_crash_without_duplicate_apply() -> None:
    effect_app = create_effect_sim_app()
    async with run_asgi_server(effect_app) as effect_origin:
        task = _make_task(
            user_id="operator_a1",
            profile_id="prof",
            allowed_origins=(effect_origin,),
            read_only=False,
            allowed_tools=("effect.apply", "effect.inspect_state"),
        )
        adapter = EffectSimAdapter()

        # First attempt crashes after persisting effect; secret in params must be redacted
        res1, rcpt1 = await adapter.apply_effect(
            task=task,
            origin=effect_origin,
            run_id="run-a08",
            step_id="step-1",
            attempt=1,
            operation_key="op-a08-k1",
            asset_id="bomba-34-a1",
            action="ack_alarm",
            params={"alarm_id": "ALM-3401", "api_key": "super-secret-value"},
            fail_after_apply=True,
        )
        assert res1 is None
        assert rcpt1.outcome == ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION
        assert rcpt1.redacted_args["params"]["api_key"] == REDACTED_PLACEHOLDER
        assert not contains_unredacted_secret(rcpt1.model_dump())

        # Reconcile checks GET /api/effects/state and confirms single execution without replay
        ok, existing, rcpt2 = await adapter.reconcile_effect(
            task=task,
            origin=effect_origin,
            run_id="run-a08",
            step_id="step-1",
            attempt=2,
            operation_key="op-a08-k1",
            asset_id="bomba-34-a1",
            action="ack_alarm",
            params={"alarm_id": "ALM-3401", "api_key": "super-secret-value"},
        )
        assert ok is True
        assert existing is not None
        assert rcpt2.tool_id == "effect.inspect_state"
        assert rcpt2.outcome == ReceiptOutcome.SUCCEEDED
        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1


@pytest.mark.n2
async def test_session_security_hardening_dot_missing_meta_and_takeover_owner(
    tmp_path: Path,
) -> None:
    scada_app = create_scada_app(fixture_mode="default")
    profile_root = tmp_path / "profiles"

    async with run_asgi_server(scada_app) as scada_origin:
        async with SessionManager(profile_root, headless=True) as mgr:
            # Single-dot segment collapse must be rejected
            for bad_args in (
                (".", "p1", "scada"),
                ("u1", ".", "scada"),
                ("u1", "p1", "."),
                (" . ", "p1", "scada"),
            ):
                with pytest.raises(ValueError):
                    await mgr.open_session(*bad_args, (scada_origin,))

            sess = await mgr.open_session("op1", "p1", "scada", (scada_origin,))
            # owner=None must NOT bypass takeover ownership check
            await mgr.request_takeover(sess.session_id, owner="alice", reason="manual")
            with pytest.raises(TakeoverStateError):
                await mgr.release_takeover(sess.session_id, owner=None)
            state = await mgr.get_session_state(sess.session_id)
            assert state is not None
            assert state.takeover_active is True
            assert state.takeover_owner == "alice"

        # Deleted session_meta.json on populated profile_dir must fail closed
        meta_path = profile_root / "op1" / "p1" / "scada" / "session_meta.json"
        assert meta_path.exists()
        meta_path.unlink()
        async with SessionManager(profile_root, headless=True) as mgr2:
            with pytest.raises(SessionOwnershipError):
                await mgr2.open_session("op1", "p1", "scada", (scada_origin,))
            assert not meta_path.exists()


@pytest.mark.n2
async def test_adapter_alias_scope_areas_unreachable_and_verifier_hardening(
    tmp_path: Path,
) -> None:
    ref_time = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    creds = MappingCredentialProvider(
        {
            ("operator_ro", "prof", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "prof", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
        SessionManager(tmp_path / "profiles", headless=True) as mgr,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        task = _make_task(
            user_id="operator_ro",
            profile_id="prof",
            allowed_origins=(scada_origin, maint_origin),
        )

        # 1. Configured alias resolution ("Pump 34", "P-34") succeeds
        res_alias, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-alias-1",
            target_asset_query="Pump 34",
            reference_time=ref_time,
        )
        assert res_alias.status == TaskStatus.SUCCEEDED
        assert "ALM-3401" in res_alias.answer
        assert "WO-3408" in res_alias.answer

        # 2. Alias resolution preserves multi-area ambiguity
        scada_app.state.scada_state.set_mode("ambiguity")
        maint_app.state.maintenance_state.set_mode("ambiguity")
        res_amb, _ = await run_pump34_flow(
            task=task,
            config=cfg,
            session_manager=mgr,
            credential_provider=creds,
            run_id="run-alias-amb",
            target_asset_query="P-34",
            reference_time=ref_time,
        )
        assert res_amb.status == TaskStatus.WAITING_FOR_INPUT
        assert res_amb.required_action is not None
        assert "area-1" in res_amb.required_action
        assert "area-2" in res_amb.required_action

        # 3. task.scope.allowed_areas enforcement
        scoped_task = TaskSpec(
            task_id="task-area1-only",
            user_id="operator_ro",
            profile_id="prof",
            scope=TaskScope(
                facility_id="facility-a",
                allowed_origins=(scada_origin, maint_origin),
                allowed_areas=("area-1",),
                read_only=True,
            ),
            query="Check bomba 34 in area-1",
        )
        scada_adapter = ScadaAdapter(mgr, creds)
        maint_adapter = MaintenanceAdapter(mgr, creds)
        with pytest.raises(AdapterPermissionError):
            await scada_adapter.read_alarms(task=scoped_task, config=cfg, area="area-2")
        with pytest.raises(AdapterPermissionError):
            await maint_adapter.read_work_orders(task=scoped_task, config=cfg, area="area-2")

        obs_scoped, _ = await scada_adapter.read_alarms(task=scoped_task, config=cfg, area=None)
        assert obs_scoped
        assert all(o.area == "area-1" for o in obs_scoped)

        # 4. Unreachable port raises SourceUnavailableError (not raw PlaywrightError)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            unused_port = sock.getsockname()[1]
        dead_origin = f"http://127.0.0.1:{unused_port}"
        dead_cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": dead_origin, "maintenance": dead_origin},
        )
        dead_task = _make_task(
            user_id="operator_dead",
            profile_id="prof",
            allowed_origins=(dead_origin,),
        )
        with pytest.raises(SourceUnavailableError):
            await scada_adapter.read_alarms(task=dead_task, config=dead_cfg)
        with pytest.raises(SourceUnavailableError):
            await maint_adapter.read_work_orders(task=dead_task, config=dead_cfg)

        # 5. Verifier rejects reading with unit=None when allowed_units is non-empty
        verifier = Verifier()
        no_unit_reading = Observation(
            source="scada",
            session_id="sess-1",
            asset_id="bomba-34-a1",
            observed_label="bomba 34",
            value=7.5,
            unit=None,
            source_time=ref_time,
            quality=DataQuality.GOOD,
            area="area-1",
            metadata={"record_type": "reading", "record_id": "RDG-NOUNIT"},
        )
        verified_no_unit = verifier.verify_observation(
            no_unit_reading,
            task.evidence_requirements,
            config=cfg,
            reference_time=ref_time,
        )
        assert verified_no_unit.authorized_evidence is False
        assert "missing_unit" in verified_no_unit.metadata.get("rejection_reasons", [])

        # 6. Verifier.detect_contradictions checks ALL records per source (not only index 0)
        obs_scada = Observation(
            source="scada",
            session_id="sess-1",
            asset_id="bomba-34-a1",
            observed_label="bomba 34",
            value="HIGH_VIBRATION",
            unit="alarm_code",
            source_time=ref_time,
            quality=DataQuality.GOOD,
            area="area-1",
            metadata={"record_type": "alarm", "record_id": "ALM-1"},
        )
        obs_maint_1 = Observation(
            source="maintenance",
            session_id="sess-2",
            asset_id="bomba-34-a1",
            observed_label="bomba 34",
            value="Seal check",
            unit="event",
            source_time=ref_time,
            quality=DataQuality.GOOD,
            area="area-1",
            metadata={"record_type": "work_order", "order_id": "WO-1"},
        )
        obs_maint_2 = Observation(
            source="maintenance",
            session_id="sess-2",
            asset_id="bomba-99-a1",
            observed_label="bomba 34",
            value="Conflicting impeller replacement",
            unit="event",
            source_time=ref_time,
            quality=DataQuality.GOOD,
            area="area-1",
            metadata={"record_type": "work_order", "order_id": "WO-2"},
        )
        res_multi_contradiction = verifier.verify_and_synthesize(
            task=task,
            config=cfg,
            observations=[obs_scada, obs_maint_1, obs_maint_2],
            run_id="run-multi-contradiction",
            target_asset_query="bomba 34",
            reference_time=ref_time,
        )
        assert res_multi_contradiction.status == TaskStatus.PARTIAL
        assert len(res_multi_contradiction.contradictions) >= 1
        assert all(c.unresolved for c in res_multi_contradiction.contradictions)
