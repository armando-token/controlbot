# Grokbot-clon

> **Product State Label**: `flujo con emulador (N1/N2 verificados; N3 Linux pendiente)`
>
> Modular Python 3.12 industrial agent engine with frozen domain contracts, SQLite WAL crash-safe state, isolated Playwright browser sessions, deterministic evidence verification, comparative benchmarks, isolated M7 continuous-improvement factory, and offline M8 deployment/rollback packaging.

---

## 1. Honest Platform & Verification Status (`N1` / `N2` vs `PENDING_N3_LINUX_ENV`)

- **Verified natively on macOS ARM64 (`Darwin 27.0.0`, `arm64`, Python `3.12.15`, Playwright `1.64.0` + Chromium `1248`)**:
  - **`N1` (Deterministic Unit)**: `97/97` tests pass (`contracts`, `storage`, `engine`, `verifier`, `desktop`, `doctor`, `n3_probe`, `benchmarks`, `factory`, `deploy`).
  - **`N2` (Real Local Integration & Acceptance)**: `41/41` integration tests + `19/19` non-N3 acceptance tests (`A01`–`A10`, `A11` loopback, `A12` Facility A & Facility B Area-2, `A13`, `A14`, `M5` benchmark, `M6` factory & deploy/rollback) pass against live local FastAPI/uvicorn apps, real SQLite WAL, headless Playwright contexts, real `SIGKILL` subprocess crash recovery, and loopback mock OpenAI HTTP servers.
- **Pending Target Linux Host (`PENDING_N3_LINUX_ENV`)**:
  - **`N3` (Linux Outbound-Blocked LAN + Real Local LLM + Live AT-SPI/X11/Wayland)**: `2` acceptance tests (`test_a11_linux_kernel_netns_and_local_llm_n3`, `test_m6_n3_linux_offline_gate`) are explicitly marked `@pytest.mark.n3` and skipped with `PENDING_N3_LINUX_ENV` on Darwin. Linux execution scripts (`scripts/verify_n3_linux.sh`), `systemd` unit (`deploy/grokbot.service`), `Containerfile`, and `deploy/OFFLINE_RUNBOOK.md` are packaged and ready for target Linux hardware.

---

## 2. Architecture & Directory Layout

```text
Grokbotclon/
├── Makefile                    # Reproducible verification, demo, offline & benchmark targets
├── pyproject.toml              # Python >=3.12,<3.13, dependencies, ruff & mypy --strict config
├── uv.lock                     # Pinned 41-package dependency lockfile (offline-verified)
├── THIRD_PARTY_NOTICES.md      # Exact locked package licenses & clean-room provenance policy
├── src/
│   ├── contracts/              # Frozen Pydantic models, enums, budgets & secret redaction
│   ├── storage/                # SQLite WAL store, migrations, 6-step leases, receipts, audit log
│   ├── engine/                 # Coordinator, hierarchical shared budgets, loop detector, ToolRegistry
│   ├── model/                  # ModelClient protocol, EmulatedModelClient, LocalHttpModelClient
│   ├── adapters/               # Playwright SessionManager, SCADA/Maint/Effect adapters, Verifier, Desktop probe
│   ├── web/                    # FastAPI local operator API & Jinja2 observability HTML UI
│   ├── factory/                # M7 isolated local software factory (WAL DB, PolicyGuard, 2-candidate demo)
│   ├── runtime.py              # Unified runtime wiring (StorageRepo + Playwright + Engine + Web)
│   ├── doctor.py               # N1/N2/N3 environment diagnostics (`make doctor`)
│   ├── n3_probe.py             # Strict Linux N3 / A11 / AT-SPI / local LLM probe
│   └── demo.py                 # Reproducible Pump 34 multi-source demo (`make demo`)
├── lab/
│   ├── scada_app/              # Synthetic SCADA web app (login, alarms, readings, duplicate areas, 401/503)
│   ├── maintenance_app/        # Synthetic Maintenance CMMS web app (work orders, contradictory fixtures)
│   ├── effect_sim/             # Idempotency-key & crash-before-confirm side-effect simulator
│   └── configs/                # facility_a.json (Pump 34) & facility_b.json (Pump 77 / Area 2)
├── benchmarks/                 # RuleBasedBaseline vs GrokbotEngine paired benchmark harness (`make bench`)
├── deploy/                     # M8 declarative config validator, SHA-256 packager, state-preserving rollback
├── scripts/                    # verify_n3_linux.sh (target Linux N3 verification gate)
├── docs/
│   ├── research/               # Clean-room comparative dossiers (13 external systems)
│   └── decisions/              # ADR-0001..0003
├── ops/
│   ├── NIGHT_STATE.md          # Host inventory, night budget window & milestone state
│   ├── BACKLOG.md              # Prioritized backlog (M0-M8 + BLOCKED_ENV N3)
│   └── NIGHT_REPORT.md         # Verifiable closeout report (Megaplan §8)
└── tests/
    ├── unit/                   # N1 deterministic unit tests
    ├── integration/            # N2 multi-process, Playwright, lab HTTP & SIGKILL tests
    └── acceptance/             # Megaplan A01-A14 & M6 acceptance oracle tests
```

---

## 3. Prerequisites & Zero-Network Policy

- **Host Requirements (N1/N2)**:
  - Python `3.12.x` (`>=3.12,<3.13`)
  - `uv` (`0.13.0+`), `make`, `git`, SQLite 3 with WAL support
  - Cached Playwright Chromium binaries (`playwright==1.64.0`, `chromium-1248`, `chromium_headless_shell-1248`)
- **Additional Target Host Requirements (N3 Linux)**:
  - Linux kernel host with `ip netns` / `nftables` or `iptables` outbound-blocking (`A11`)
  - Local OpenAI/llama.cpp-compatible inference server (`ollama`, `llama-server`, or `vllm`) with pinned weights
  - Linux desktop session (`AT-SPI`, `X11`/`XWayland` or `Wayland`) for live desktop probes
- **Offline Rule**: Zero internet downloads are performed during `make check`, `make test-offline`, `make demo`, or `make bench`. Lockfile integrity is checked offline via `uv lock --check --offline`.

---

## 4. Reproducible Commands Reference

| Command | Prerequisites | Expected Output | Exit Code | Evidence Level |
|---|---|---|---|---|
| `make doctor` | `.venv` + `uv` + Playwright cache | `n1_ready=True \| n2_ready=True \| n3_status=PENDING_N3_LINUX_ENV` | `0` | N1 / N2 |
| `make lint` | Dev dependencies installed | `All checks passed!` (`ruff` across `src lab benchmarks deploy tests/*`) | `0` | Static |
| `make typecheck` | Dev dependencies installed | `Success: no issues found in 93 source files` (`mypy --strict`) | `0` | Static |
| `make test-n1` | `.venv` | `97 passed` | `0` | N1 |
| `make test-n2` | `.venv` + cached Chromium `1248` | `41 passed` | `0` | N2 |
| `make test-acceptance` | `.venv` + cached Chromium `1248` | `19 passed, 2 deselected` (`n3` deselected) | `0` | N2 |
| `make test` | `.venv` + cached Chromium `1248` | Runs N1 + N2 + acceptance, prints `[PENDING_N3_LINUX_ENV]` notice on non-Linux | `0` | N1 / N2 |
| `make test-n3` | `.venv` (Linux + LLM for live pass) | On macOS: `2 skipped` (`PENDING_N3_LINUX_ENV`); on Linux N3: `2 passed` | `0` | N3 (`PENDING_N3_LINUX_ENV` on Darwin) |
| `make test-offline` | `.venv` + `deploy/install_config.yaml` | Validates `install_config.yaml`, runs `20` offline/loopback/factory/deploy tests + `test-n3`, prints `[PENDING_N3_LINUX_ENV]` | `0` | N1 / N2 (+ N3 skip reason) |
| `make check` | Full N1/N2 environment | Runs `doctor`, `lint`, `typecheck`, `test` | `0` | N1 / N2 |
| `make demo` | `.venv` + cached Chromium `1248` | Pump 34 demo: `Status: succeeded (ok=True)`, `ALM-3401` + `WO-3408`, `redaction_clean=True` | `0` | N2 |
| `make bench` | `.venv` + cached Chromium `1248` | Comparative report: `RuleBasedBaseline` `1/13` vs `GrokbotEngine` `13/13`, `A12 Engine LOC Delta=0`, `A11=PENDING_N3_LINUX_ENV` | `0` | N1 / N2 |

### Additional Direct CLIs

| Command | Purpose | Expected Output & Exit Code |
|---|---|---|
| `uv run python -m src.factory.demo --json` | M7 2-candidate software factory demo on isolated lab git repo + `factory.db` | Exit `0`; `"ok": true`, `"rollback_verified": true`, `cand-1-index` promoted (`100.0 -> 1.0`), `cand-2-skip-area` rejected (`wrong_asset_attributions=2`) |
| `uv run python -m benchmarks.runner --mode local_http --json` | Paired benchmark using loopback OpenAI-compatible mock LLM | Exit `0`; `model_type="local_http_mock"`, `13/13` (`100.0%`), `promotion_eligible=true` |
| `uv run python -m deploy.config --config deploy/install_config.yaml --json` | Fail-closed validation of declarative offline deploy config + facility cross-check | Exit `0` when valid; Exit `1` (`stderr`) on unconfigured/external origins |
| `uv run python -m deploy.package --config deploy/install_config.yaml --output /tmp/manifest.json --json` | Build SHA-256 `ReleaseManifest` with `state_preserve_paths` and honest `n3_status` | Exit `0`; deterministic JSON manifest |
| `uv run python -m deploy.rollback --manifest /tmp/nonexistent_manifest.json` | State-preserving rollback error handling check | Exit `1`; concise diagnostic on `stderr` without `argparse` `"usage:"` |
| `uv run python -m src.n3_probe --strict --json` | Strict Linux N3 readiness probe | Exit `1` (`PENDING_N3_LINUX_ENV`) on macOS; Exit `0` (`READY`) on compliant Linux N3 host |
| `./scripts/verify_n3_linux.sh` | Full Linux N3 verification gate (netns/firewall, blocked `1.1.1.1:443`, N3 probe, `pytest -m n3`) | Exit `1` (`[PENDING_N3_LINUX_ENV]`) on macOS; Exit `0` on compliant Linux N3 host |

---

## 5. Local Web API & Observability UI

Start locally bound to loopback (`127.0.0.1` only):
```bash
uv run uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 8000
```
- **HTML UI**: `GET /`, `GET /tasks/{run_id}` (auto-escaped Jinja2 templates, zero external CDN requests)
- **JSON API**:
  - `GET /health`
  - `POST /api/tasks` (cross-checks `allowed_origins` against `installation_config_path` / runtime facility config before persistence; returns `422` on disallowed origins, `409` on state/plan conflicts)
  - `GET /api/tasks`, `GET /api/tasks/{run_id}`
  - `POST /api/tasks/{run_id}/cancel`, `POST /api/tasks/{run_id}/resume`
  - `GET /api/sessions`, `POST /api/sessions/{session_id}/takeover`, `POST /api/sessions/{session_id}/release`

---

## 6. Next Steps for Target Linux Pilot (`N3`)

See `deploy/OFFLINE_RUNBOOK.md` and `scripts/verify_n3_linux.sh` to stage the offline wheelhouse, Chromium `1248`, pinned local LLM weights, and Linux network namespace / `nftables` outbound isolation on the target Linux host.
