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
- [x] `B-M2-01`: Implement `src/storage/` SQLite WAL repository, schema migrations, short transactions, 6-step lease fencing (`lease_owner`, `lease_expiry`, `lease_generation`), persistent `operation_key`, and redacted `ActionReceipt` store.
- [x] `B-M2-02`: Implement `src/engine/` coordinator & state machine, root-shared hierarchical budget reservation/reconciliation (`depth=1`, `2` children, `16` tools, `8` model calls, `120s`, `24k` tokens, `1` retry), repeated/alternating cycle detector (`A06`, `A07`), and cascading cancellation (`A09`).
- [x] `B-M2-03`: Implement `src/model/` (`ModelClient` protocol + deterministic `EmulatedModelClient`) and `ToolRegistry` (origin allowlist, permission checks, secret redaction before return).
- [x] `B-M2-04`: Write N1 unit tests for lifecycle, concurrency, budgets, loop detection, cancellation, and restart reconciliation (`A06`, `A07`, `A08` unit, `A09`, `A14` unit).
- [x] `B-M3-01`: Implement `lab/scada_app/`, `lab/maintenance_app/`, `lab/effect_sim/`, and `lab/configs/facility_a.json` (Pump 34 duplicate areas, stale/bad-quality modes, `401`/`503` hooks, contradictory records).
- [x] `B-M3-02`: Implement `src/adapters/` Playwright isolated `BrowserContext` + persistent profile manager per `(user, profile, app)`, config-driven industrial adapters, and value/unit/quality/contradiction verifier.
- [x] `B-M3-03`: Implement `src/web/` FastAPI API + minimal HTML observability UI and N2 integration tests (`tests/integration/`).

## P2 — Hardening, Local LLM HTTP Client & Benchmarks (M4 + M5)
- [x] `B-M4-01`: Implement `LocalHttpModelClient` (OpenAI/llama.cpp-compatible HTTP server, structured/tool-call validation, conservative `estimated` token fallback) + mock HTTP N2 tests + Linux N3 probe script.
- [x] `B-M4-02`: Implement human takeover lock (`409` on active lease) and auth-expiry pause/resume (`A10`), plus real subprocess `SIGKILL` crash recovery (`A08`, `A14`).
- [x] `B-M4-03`: Implement Linux AT-SPI/X11/Wayland desktop adapter interface + capability probe (`PENDING_N3_LINUX_ENV` on macOS).
- [x] `B-M4-04`: Implement `tests/acceptance/` (`A01`–`A14`, labeling N3 checks honestly) and `make demo` (Pump 34 flow).
- [x] `B-M5-01`: Implement `benchmarks/` (`>=12` scenarios, fixed baseline vs engine, reproducible JSON/MD reports, `make bench`).
- [x] `B-M5-02`: Implement `lab/configs/facility_b.json` + Area 2 fixtures and verify `A12` config-only portability.

## P3 — Software Factory, Packaging & Final Report (M6 + M7)
- [x] `B-M6-01`: Implement `src/factory/` (M7 autonomous local software factory with isolated DB/branch, persistent backlog lease, policy immutability guard, 1 accepted + 1 rejected asset-confusing candidate demo).
- [x] `B-M8-01`: Implement `deploy/` declarative install config, rollback manifest, offline ops runbook, `scripts/verify_n3_linux.sh`, `make test-offline`, `make test-n3`, `README.md`, and finalize `THIRD_PARTY_NOTICES.md` + `ops/NIGHT_REPORT.md`.
- [x] `B-M7-01`: Run and pass E2E Tracking suite Tiers 1–4 (`230/230`) and complete Tier 5 adversarial coverage hardening (`28/28` `@pytest.mark.tier5` covering `T5-01`–`T5-23` + R1/R2/R3 fixes on `6c0146cf`, `make check && make test-offline && make test-n3 && make demo && make bench` verified).

## P4 — Optional Capstone (`M8_CAPSTONE` — PAUSED / DEFERRED per user request `2026-11-25T21:31:15Z`)
- [ ] `B-M8-02`: `PENDING` (paused per user instruction `2026-11-25T21:31:15Z` so M1–M7 can be tested right away; prep blueprints `c7b61f5c` & `5d5e2b7b` preserved) — Optional `M8_CAPSTONE`: `AntigravityCliModelClient`, `office_artcraft.py` (`gridcraft-cli` + `wordcraft-cli`), >=3 authenticated portals with randomized canary data, and live E2E (`tests/live/`, `make demo-office-live`); requires M7 complete and explicit user resume; next command: `make check && make demo`.

## BLOCKED_ENV (N3 — Requires Target Linux Host)
- [ ] `B-N3-01`: Provision Linux host/VM/container runtime (`docker`/`lima`/`qemu`) on target Linux environment (requires Linux target hardware).
- [ ] `B-N3-02`: Execute `A11` outbound-blocked LAN verification via Linux network namespace / `iptables`, confirming external egress is blocked while internal lab apps + local LLM remain reachable (depends on `B-N3-01`).
- [ ] `B-N3-03`: Execute N3 end-to-end acceptance with real local LLM weights (`ollama`/`llama-server`) and pin exact model weights, quantization, and prompt template (depends on `B-N3-01`).
- [ ] `B-N3-04`: Execute live Linux AT-SPI + X11/XWayland vs Wayland desktop probe on a Linux desktop session (depends on `B-N3-01`).
