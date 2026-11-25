# Grokbot-clon Prioritized Backlog

> Tracks M0–M8 product milestones, M7 software factory items, and environment-blocked N3 verification items.

## P0 — Foundation, Contracts & Provenance (M0 + M1)
- [x] `B-M0-01`: Initialize git repo on `main` with repo-local identity and `.gitignore` (preserving `MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md` untouched).
- [x] `B-M0-02`: Create `pyproject.toml` (Python `>=3.12,<3.13`, `playwright==1.64.0`), `uv.lock`, `.venv`, and honest `Makefile` (`doctor`, `test`, `test-n1`, `lint`, `typecheck`, `check`, plus `exit 2` stubs for unimplemented targets).
- [x] `B-M0-03`: Implement `src/doctor.py` with injectable N1/N2/N3 checks and `PENDING_N3_LINUX_ENV` reporting on non-Linux hosts.
- [x] `B-M0-04`: Create `ops/NIGHT_STATE.md` and `ops/BACKLOG.md` documenting host inventory, budget window, and inaccessible Megaplan line-6 ChatGPT library links.
- [x] `B-M1-01`: Freeze core domain contracts in `src/contracts/` (`common.py`, `redaction.py`, `enums.py`, `budgets.py`, `models.py`, `planning.py`) with `mypy --strict` and N1 unit tests.
- [x] `B-M1-02`: Author comparative research dossiers in `docs/research/` (Rakazo, Hermes Agent, OpenClaw, OpenMausBot, NanoClaw, IronClaw, OpenHands, Playwright/MCP/agent-browser/Browser Use, Cua/Munim/CUA-JEV).
- [x] `B-M1-03`: Author `ADR-0001`, `ADR-0002`, `ADR-0003` in `docs/decisions/` and `THIRD_PARTY_NOTICES.md` from exact `uv.lock` versions.

## P1 — Core Engine, Storage & Synthetic Lab (M2 + M3)
- [ ] `B-M2-01`: Implement `src/storage/` SQLite WAL repository, schema migrations, short transactions, 6-step lease fencing (`lease_owner`, `lease_expiry`, `lease_generation`), persistent `operation_key`, and redacted `ActionReceipt` store.
- [ ] `B-M2-02`: Implement `src/engine/` coordinator & state machine, root-shared hierarchical budget reservation/reconciliation (`depth=1`, `2` children, `16` tools, `8` model calls, `120s`, `24k` tokens, `1` retry), repeated/alternating cycle detector (`A06`, `A07`), and cascading cancellation (`A09`).
- [ ] `B-M2-03`: Implement `src/model/` (`ModelClient` protocol + deterministic `EmulatedModelClient`) and `ToolRegistry` (origin allowlist, permission checks, secret redaction before return).
- [ ] `B-M2-04`: Write N1 unit tests for lifecycle, concurrency, budgets, loop detection, cancellation, and restart reconciliation (`A06`, `A07`, `A08` unit, `A09`, `A14` unit).
- [ ] `B-M3-01`: Implement `lab/scada_app/`, `lab/maintenance_app/`, `lab/effect_sim/`, and `lab/configs/facility_a.json` (Pump 34 duplicate areas, stale/bad-quality modes, `401`/`503` hooks, contradictory records).
- [ ] `B-M3-02`: Implement `src/adapters/` Playwright isolated `BrowserContext` + persistent profile manager per `(user, profile, app)`, config-driven industrial adapters, and value/unit/quality/contradiction verifier.
- [ ] `B-M3-03`: Implement `src/web/` FastAPI API + minimal HTML observability UI and N2 integration tests (`tests/integration/`).

## P2 — Hardening, Local LLM HTTP Client & Benchmarks (M4 + M5)
- [ ] `B-M4-01`: Implement `LocalHttpModelClient` (OpenAI/llama.cpp-compatible HTTP server, structured/tool-call validation, conservative `estimated` token fallback) + mock HTTP N2 tests + Linux N3 probe script.
- [ ] `B-M4-02`: Implement human takeover lock (`409` on active lease) and auth-expiry pause/resume (`A10`), plus real subprocess `SIGKILL` crash recovery (`A08`, `A14`).
- [ ] `B-M4-03`: Implement Linux AT-SPI/X11/Wayland desktop adapter interface + capability probe (`PENDING_N3_LINUX_ENV` on macOS).
- [ ] `B-M4-04`: Implement `tests/acceptance/` (`A01`–`A14`, labeling N3 checks honestly) and `make demo` (Pump 34 flow).
- [ ] `B-M5-01`: Implement `benchmarks/` (`>=12` scenarios, fixed baseline vs engine, reproducible JSON/MD reports, `make bench`).
- [ ] `B-M5-02`: Implement `lab/configs/facility_b.json` + Area 2 fixtures and verify `A12` config-only portability.

## P3 — Software Factory, Packaging & Final Report (M6 + M7)
- [ ] `B-M6-01`: Implement `src/factory/` (M7 autonomous local software factory with isolated DB/branch, persistent backlog lease, policy immutability guard, 1 accepted + 1 rejected asset-confusing candidate demo).
- [ ] `B-M8-01`: Implement `deploy/` declarative install config, rollback manifest, offline ops runbook, `make test-offline`, `README.md`, and finalize `THIRD_PARTY_NOTICES.md` + `ops/NIGHT_REPORT.md`.
- [ ] `B-M7-01`: Run and pass parallel E2E Tracking suite Tiers 1–4 and complete Tier 5 adversarial coverage hardening.

## BLOCKED_ENV (N3 — Requires Target Linux Host)
- [ ] `B-N3-01`: Provision Linux host/VM/container runtime (`docker`/`lima`/`qemu`) on target Linux environment.
- [ ] `B-N3-02`: Execute `A11` outbound-blocked LAN verification via Linux network namespace / `iptables`, confirming external egress is blocked while internal lab apps + local LLM remain reachable.
- [ ] `B-N3-03`: Execute N3 end-to-end acceptance with real local LLM weights (`ollama`/`llama-server`) and pin exact model weights, quantization, and prompt template.
- [ ] `B-N3-04`: Execute live Linux AT-SPI + X11/XWayland vs Wayland desktop probe on a Linux desktop session.
