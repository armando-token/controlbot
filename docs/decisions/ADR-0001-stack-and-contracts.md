# ADR-0001: Python 3.12 Modular Monolith Stack & Frozen Core Contracts

- **Status**: Accepted (M1)
- **Date**: 2026-11-25
- **Owner**: Orquestador e integrador (`teamwork_worker_m1_1`)
- **Governing Specification**: `MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md` (§1, §3.2–§3.3, §4.1–§4.2)

---

## Context
Grokbot-clon requires a deterministic, verifiable, single-host-capable agent engine and synthetic industrial laboratory (`F03`–`F18`) running natively on Linux (and verifiable at N1/N2 levels on macOS ARM64 during development), with strict boundaries between:
- Domain contracts (`src/contracts/`)
- SQLite WAL storage (`src/storage/`)
- Orchestration engine, shared budgets, loop control & recovery (`src/engine/`)
- Model client abstraction (`src/model/`)
- Isolated browser & industrial adapters (`src/adapters/`)
- Local observability web UI (`src/web/`)

## Decision
1. **Runtime & Language**: Python `>=3.12,<3.13` managed via `uv` (`uv.lock` + `.venv`), structured as a single modular monolith under `src/`.
2. **Frozen Domain Contracts (`src/contracts/`)**:
   - Immutable Pydantic v2 models (`FrozenModel` with `frozen=True, extra="forbid"`) for `TaskScope`, `EvidenceRequirements`, `TaskSpec`, `Run`, `Step`, `RetryPolicy`, `ToolSpec`, `ActionReceipt`, `Observation`, `ContradictionClaim`, `ContradictionRecord`, `ExecutionMetrics`, `Result`, `BudgetConfig`, `BudgetUsage`, `PlanStep`, and `ExecutionPlan`.
   - `TaskStatus(StrEnum)` with 8 states (`queued`, `running`, `waiting_for_input`, `recovering`, `succeeded`, `partial`, `failed`, `cancelled`) and immutable terminal states (`succeeded`, `partial`, `failed`, `cancelled`).
   - Mandatory UTC-aware timestamp validation (`ensure_utc`) and `HttpOrigin` validation (`http`/`https` without embedded userinfo/paths/queries).
   - Fail-closed secret redaction (`src/contracts/redaction.py`) enforced directly inside `ActionReceipt` validation (`contains_unredacted_secret(redacted_args) == False`).
   - Pre-execution DAG & scope/budget/verifier validation (`validate_plan_for_task` / `assert_valid_plan`).
3. **Web, Browser & Quality Tooling**:
   - `fastapi`, `uvicorn[standard]`, `httpx`, `jinja2` for local API/UI and synthetic lab apps.
   - `playwright==1.64.0` (aligned with host-cached `chromium-1248`) for isolated browser execution.
   - `pytest`, `pytest-asyncio`, `ruff`, and `mypy --strict` (`pydantic.mypy` plugin) as mandatory verification gates (`make check`).
4. **Clean-Room Ownership**: All orchestration, state transitions, budget accounting, loop detection, recovery, and verification are original Grokbot-clon implementations built from `src/contracts/` (never vendoring Rakazo, Hermes, OpenClaw, or OpenMausBot).

## Alternatives Considered
1. **Multi-service distributed architecture (Celery/Redis/Postgres)**: Rejected for MVP; introduces unnecessary operational complexity and failure modes on single-host/air-gapped Linux installations. Megaplan §4.1 mandates measuring core bottlenecks before splitting.
2. **Plain `dataclasses` or `TypedDict`**: Rejected; lacks runtime boundary validation, `extra="forbid"`, strict UTC normalization, and JSON schema/round-tripping required for `ModelClient`, `ToolRegistry`, and `ExecutionPlan`.
3. **Adopting OpenClaw, Hermes Agent, or Rakazo as core runtime**: Rejected; violates Megaplan §1 clean-room ownership rule (*"Implementar nuestros propios mecanismos de orquestación, presupuesto, recuperación y verificación"*) and introduces incompatible stack/budget semantics (Node/TS or non-hierarchical/non-persistent budgets).

## Consequences
- **Positive**: Fast deterministic N1 testing (`~0.1s` for contract suite), strict static type safety (`mypy --strict`), single-language debugging, and zero cross-module contract drift once M1 freezes `src/contracts/`.
- **Negative / Trade-offs**: Any post-M1 modification to frozen contracts in `src/contracts/` requires a new superseding ADR and corresponding `src/storage/` migration.

## Revocation Conditions
- Split the monolith into separate worker processes or services only if reproducible benchmarks demonstrate an unresolvable single-process CPU/GIL bottleneck after profiling.
- Replace or extend `src/contracts/` only via an explicit ADR approved by the integrator before downstream M2–M7 consumers depend on changed fields.
