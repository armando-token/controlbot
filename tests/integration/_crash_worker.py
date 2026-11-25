"""Subprocess crash worker for real SIGKILL A08 and A14 integration/acceptance tests."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.adapters import EffectSimAdapter, get_effect_tool_specs
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import EffectClass, TaskStatus
from src.contracts.models import TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator, CoordinatorConfig
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model.emulator import EmulatedModelClient, EmulatedTurn
from src.model.protocol import (
    BudgetRemaining,
    ModelDecision,
    ModelToolCall,
    ModelUsage,
    PromptContext,
)
from src.storage.repo import StorageRepo


def _build_a08_runtime(
    *,
    db_path: Path,
    effect_origin: str,
    pause_after_apply: bool,
) -> tuple[StorageRepo, Coordinator]:
    repo = StorageRepo(db_path)
    repo.init_db()
    adapter = EffectSimAdapter()
    specs = get_effect_tool_specs((effect_origin,))
    registry = ToolRegistry()

    async def _apply_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        task = repo.get_task_spec(ctx.task_id)
        payload, receipt = await adapter.apply_effect(
            task=task,
            origin=ctx.target_origin or effect_origin,
            run_id=ctx.run_id,
            step_id=ctx.step_id,
            attempt=ctx.attempt,
            operation_key=str(
                ctx.idempotency_key or args.get("operation_key") or ctx.operation_key
            ),
            asset_id=str(args["asset_id"]),
            action=str(args["action"]),
            params=args.get("params") if isinstance(args.get("params"), dict) else None,
            fail_after_apply=False,
        )
        if pause_after_apply:
            print("READY_TO_KILL", flush=True)
            await asyncio.sleep(60.0)
        return {
            "output": payload or {},
            "observed_before": receipt.observed_before,
            "observed_after": receipt.observed_after,
            "evidence_refs": list(receipt.evidence_refs),
        }

    async def _reconciler(
        op_key: str,
        idem_key: str,
        ctx: ToolExecutionContext,
    ) -> tuple[bool, dict[str, Any] | None]:
        task = repo.get_task_spec(ctx.task_id)
        state = await adapter.inspect_state(
            task=task,
            origin=ctx.target_origin or effect_origin,
            operation_key=idem_key or op_key,
        )
        existing = state.get("effect")
        if isinstance(existing, dict):
            return True, existing
        return False, {"confirmed_unapplied": True}

    registry.register(
        specs["effect.apply"],
        _apply_handler,
        reconciler=_reconciler,
        supports_idempotency=True,
    )

    def _turn_factory(
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        budget_remaining: BudgetRemaining,
    ) -> EmulatedTurn:
        del tools, budget_remaining
        usage = ModelUsage(
            prompt_tokens=30,
            completion_tokens=15,
            total_tokens=45,
            usage_mode="actual",
        )
        if not prompt_ctx.history and not prompt_ctx.observations:
            return EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="effect.apply",
                        args={
                            "operation_key": "op-a08-sigkill-1",
                            "asset_id": "bomba-34-a1",
                            "action": "ack_alarm",
                            "params": {"alarm_id": "ALM-3401"},
                        },
                        target_origin=effect_origin,
                    ),
                    usage=usage,
                )
            )
        return EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Effect applied and verified once.",
                usage=usage,
            )
        )

    coord = Coordinator(
        repo,
        EmulatedModelClient(mode="custom", turn_factory=_turn_factory),
        registry,
        config=CoordinatorConfig(
            coordinator_id="crash-worker-a08" if pause_after_apply else "recover-worker-a08",
            lease_ttl_seconds=1.0,
            default_granted_permissions=("effect:read", "effect:write"),
        ),
    )
    return repo, coord


def _build_a14_runtime(
    *,
    db_path: Path,
    pause_in_step2: bool,
) -> tuple[StorageRepo, Coordinator]:
    repo = StorageRepo(db_path)
    repo.init_db()
    registry = ToolRegistry()

    read_spec = ToolSpec(
        tool_id="diag.read",
        version="1.0.0",
        input_schema={"type": "object", "properties": {"probe": {"type": "string"}}},
        output_schema={"type": "object"},
        permissions=("diag:read",),
        allowed_origins=(),
        effect_class=EffectClass.READ,
        timeout_s=30.0,
        verifier_name="verify_diag",
    )

    async def _diag_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del ctx
        return {
            "output": {
                "probe": args.get("probe"),
                "progress_token": f"tok-{args.get('probe')}",
            }
        }

    registry.register(read_spec, _diag_handler)

    class _A14CrashModel:
        async def decide(
            self,
            prompt_ctx: PromptContext,
            tools: Sequence[ToolSpec],
            budget_remaining: BudgetRemaining,
        ) -> ModelDecision:
            del tools, budget_remaining
            usage = ModelUsage(
                prompt_tokens=100,
                completion_tokens=40,
                total_tokens=140,
                usage_mode="actual",
            )
            called = [
                h.get("args", {}).get("probe")
                for h in prompt_ctx.history
                if isinstance(h, dict)
            ]
            if len(called) == 0:
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="diag.read",
                        args={"probe": "step1"},
                    ),
                    usage=usage,
                )
            if pause_in_step2:
                print("READY_TO_KILL", flush=True)
                await asyncio.sleep(60.0)
            return ModelDecision(
                decision_type="final",
                final_answer="A14 recovered cleanly.",
                usage=usage,
            )

    coord = Coordinator(
        repo,
        _A14CrashModel(),
        registry,
        config=CoordinatorConfig(
            coordinator_id="crash-worker-a14" if pause_in_step2 else "recover-worker-a14",
            lease_ttl_seconds=1.0,
            default_granted_permissions=("diag:read",),
        ),
    )
    return repo, coord


async def _run(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path)
    if args.mode == "run_a08":
        _, coord = _build_a08_runtime(
            db_path=db_path,
            effect_origin=args.effect_origin,
            pause_after_apply=True,
        )
        spec = TaskSpec(
            task_id="task-a08-sigkill",
            user_id="op",
            profile_id="prof",
            scope=TaskScope(
                facility_id="facility-a",
                allowed_origins=(args.effect_origin,),
                allowed_tools=("effect.apply",),
                read_only=False,
            ),
            query="Apply effect once",
        )
        coord.submit_task(spec, run_id=args.run_id)
        await coord.run_until_settled(args.run_id)
        return 0

    if args.mode == "recover_a08":
        repo, coord = _build_a08_runtime(
            db_path=db_path,
            effect_origin=args.effect_origin,
            pause_after_apply=False,
        )
        summary = await coord.recover_inflight_runs("recover-worker-a08")
        res = await coord.run_until_settled(args.run_id)
        snap = repo.get_run_snapshot(args.run_id)
        print(
            json.dumps(
                {
                    "summary": summary.model_dump(mode="json"),
                    "status": res.status.value,
                    "step_statuses": [s.status.value for s in snap.steps],
                    "tool_calls_used": snap.budget_usage.tool_calls_used,
                }
            ),
            flush=True,
        )
        return 0 if res.status == TaskStatus.SUCCEEDED else 1

    if args.mode == "run_a14":
        _, coord = _build_a14_runtime(db_path=db_path, pause_in_step2=True)
        spec = TaskSpec(
            task_id="task-a14-sigkill",
            user_id="op",
            profile_id="prof",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Run budget recovery test",
            budget=BudgetConfig(max_tool_calls=6, max_model_calls=6, max_total_tokens=2000),
        )
        coord.submit_task(spec, run_id=args.run_id)
        await coord.run_until_settled(args.run_id)
        return 0

    if args.mode == "recover_a14":
        repo, coord = _build_a14_runtime(db_path=db_path, pause_in_step2=False)
        summary = await coord.recover_inflight_runs("recover-worker-a14")
        pre_usage = repo.get_budget_usage("task-a14-sigkill")
        pre_sigs = repo.get_step_signatures(args.run_id)
        res = await coord.run_until_settled(args.run_id)
        post_usage = repo.get_budget_usage("task-a14-sigkill")
        print(
            json.dumps(
                {
                    "summary": summary.model_dump(mode="json"),
                    "pre_usage": pre_usage.model_dump(mode="json"),
                    "pre_signatures_count": len(pre_sigs),
                    "status": res.status.value,
                    "post_usage": post_usage.model_dump(mode="json"),
                    "within_limits": post_usage.within_limits(
                        BudgetConfig(max_tool_calls=6, max_model_calls=6, max_total_tokens=2000)
                    ),
                }
            ),
            flush=True,
        )
        return 0 if res.status == TaskStatus.SUCCEEDED else 1

    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--effect-origin", default="")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
