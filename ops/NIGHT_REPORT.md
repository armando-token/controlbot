# NIGHT_REPORT — Grokbot-clon

## Estado verificable y siguiente acción
- **Estado del producto**: **`flujo con emulador`**
- **Estado general de cierre M0–M7-T3**: **VERIFICADO en N1 + N2 (Darwin ARM64)**; **N3 Linux (`A11` kernel `netns`/`iptables`, LLM local con pesos reales y AT-SPI/X11/Wayland) = `PENDING_N3_LINUX_ENV`**.
- **Siguiente acción ejecutable**: **M7 Tier 4 y Tier 5 Adversarial Hardening** contra el conjunto publicado en `tests/e2e/` (`uv run pytest tests/e2e -m "tier4" -v`), seguido de la validación N3 en host Linux destino (`./scripts/verify_n3_linux.sh`).

---

## 1. Commit / Punto de recuperación y entorno ejecutado

- **Rama activa**: `main`
- **Commit de código y pruebas M7-T3 verificado**: `b5676156c2877d44cc957a2f245dfdf3d3e8cb43` (`fix(m7-t3): enforce case-insensitive policy immutability & unmerged 120000 symlink diff checks`)
- **Cadena de commits de hitos en `main`**:
  - `d95e98e` — `chore(m1): initialize repo, diagnostics, frozen contracts, research & ADRs`
  - `ccadffc` — `M1: remediate mypy e2e exclusion, redaction hardening, contract invariants, and doctor checks`
  - `7eb9885` — `Complete M2-M4 core engine, lab, adapters, web UI, local HTTP model, and hardening fixes`
  - `d2a027d` — `feat(m5): add A12 Area-2 portability and comparative benchmark harness`
  - `0e5a3ac` — `chore(m4): apply Iteration 4 hardening pass`
  - `5cc4962` — `fix(m5): enforce solo verifier checks and honest benchmark trial details`
  - `6a11a47` — `feat(m6): add software factory, offline deploy/rollback, N3 scripts & integration fixes`
  - `2a0be81` — `docs(m6): finalize README, third-party notices, night state, backlog & NIGHT_REPORT`
  - `5be7bbd` — `fix(m7-t1): align adapters, web origins/tracing, area2 fixtures, benchmarks, factory & deploy for Tier 1 E2E`
  - `2bca0dd` — `docs(night-report): align NIGHT_REPORT format, exact status label & M7-T1 commit SHA`
  - `16acc13` — `fix(m7-t2): resolve policy denial evidence, config validation, dual backend routing, benchmark gate, N3 summary & factory CLI`
  - `95d9fe1` — `docs(night-report): update NIGHT_REPORT with M7-T2 commit SHA 16acc13 and verification counts`
  - `93b7e0c` — `fix(m7-t3): resolve crash recovery, poller loop guard, depth=1 delegation, factory/deploy/benchmark CLIs & ambiguity observations`
  - `03f681b` — `docs(night-report): update NIGHT_REPORT with M7-T3 commit SHA 93b7e0c and verification counts`
  - `25ff322` — `fix(m7-t3): harden evaluate-patch diff parsing, path normalization, symlink/forbidden checks & demo timestamp`
  - `3030735` — `docs(night-report): update NIGHT_REPORT with M7-T3-R2 commit SHA 25ff322 and verification counts`
  - `23425a0` — `fix(m7-t3): block parent, multi-hop & 120000 ancestor symlinks and handle ELOOP cleanly`
  - `ad2e6ed` — `docs(night-report): update NIGHT_REPORT with M7-T3-R3 commit SHA 23425a0 and verification counts`
  - `b567615` — `fix(m7-t3): enforce case-insensitive policy immutability & unmerged 120000 symlink diff checks`
- **Entorno ejecutado**:
  - **SO / Kernel**: `Darwin 27.0.0` (`RELEASE_ARM64_T8103`), `macOS 27.0.1` (`BuildVersion: 26A434`), arquitectura `arm64`
  - **Hardware**: Apple M1, `8` núcleos, `8 GB` RAM (`8589934592` B)
  - **Toolchain**: `Python 3.12.15`, `uv 0.13.0`, `GNU Make 3.81`, `git 2.54.0`, `SQLite 3.53.1` (WAL verificado), `playwright==1.64.0` (`chromium-1248` + `chromium_headless_shell-1248`)
  - **Niveles ejecutados en este host**: `N1 + N2` nativos; `N3` (`Linux`, `netns`/`iptables`/`nft`, pesos LLM locales, AT-SPI/X11/Wayland) = `PENDING_N3_LINUX_ENV` (sin `docker`/`lima`/`qemu`/`ollama`/`llama-server`).

---

## 2. Hitos cerrados con evidencias y hitos pendientes

| Hito | Estado | Evidencias verificadas |
|---|---|---|
| **M0 + M1** (Diagnóstico, Contratos, Investigación & ADRs) | `DONE` | `src/doctor.py`, `src/contracts/` congelado, `docs/research/` (13 proyectos), `ADR-0001..0003`, `THIRD_PARTY_NOTICES.md` |
| **M2** (Storage SQLite WAL, Engine, Budgets, Loops, Cancel, `ToolRegistry`) | `DONE` | Transacciones cortas WAL, leases con `generation`, `BudgetManager` (`depth=1`, `2` hijos, `16` tools, `8` model, `120s`, `24k` tokens), detector `A06`/`A07`, cancelación `A09` |
| **M3** (Lab Apps, Playwright aislado, Adaptadores, Verifier, Web UI) | `DONE` | `lab/scada_app`, `lab/maintenance_app`, `lab/effect_sim`, sesiones por `(user, profile, app)`, UI local XSS-safe sin CDNs externos |
| **M4** (Integración, `LocalHttpModelClient`, Takeover, `SIGKILL`, Probe N3/AT-SPI) | `DONE` | `LocalHttpModelClient` con fallback conservador `estimated`, `A10` auth-expiry pause/resume, recuperación real `SIGKILL` (`A08`/`A14`), `make demo` (`ALM-3401` + `WO-3408`) |
| **M5** (Benchmarks comparativos & Portabilidad Área 2 `A12`) | `DONE` | `lab/configs/facility_b.json` (`SC-77`/`CMMS-77`), `13/13` escenarios `GrokbotEngine` vs `1/13` `RuleBasedBaseline`, `engine_loc_delta=0` en `A12` |
| **M6** (Fábrica M7 `src/factory/`, Packaging/Rollback M8 `deploy/`, Fixes E2E/M5, Docs) | `DONE` | `src/factory/` (WAL aislado `0o700`/`0o600`, `PolicyGuard`, demo 2 candidatos con rollback verificado), `deploy/` (`install_config.yaml`, `ReleaseManifest` SHA-256, `rollback.py` preservando WAL/perfiles), `make test-offline`, `make test-n3`, 5 fixes de integración |
| **M7 (E2E Tiers 1–4 + Tier 5)** | `IN_PROGRESS` | Tier 1 (`99/99`), Tier 2 (`99/99`) y Tier 3 (`22/22`) verificados en `tests/e2e/`; pendientes Tier 4 y Tier 5 |
| **N3 Piloto Linux (`B-N3-01..04`)** | `PENDING_N3_LINUX_ENV` | `scripts/verify_n3_linux.sh`, `deploy/grokbot.service`, `deploy/Containerfile`, `deploy/OFFLINE_RUNBOOK.md` listos para host Linux |

---

## 3. Repositorios estudiados: adoptado vs descartado (documental vs medido)

### 3.1 Observación documental (`Patrón estudiado`, cero código copiado)

| Proyecto | Commit / Tag | Licencia | Adoptado como patrón de diseño | Descartado / Cuarentena |
|---|---|---|---|---|
| **Rakazo** (`elie222/rakazo`) | `bce93a9d` / `v0.16.0` | `Apache-2.0` | Separación runtime/browser, leases con `generation`, sin replay de efectos tras crash | Dependencia directa en runtime |
| **Hermes Agent** (`NousResearch/hermes-agent`) | `2fcdbfea` / `v0.23.4` | `MIT` | Controlador puro `(tool, args, result_hash)` para repeticiones y ciclos alternantes (`A06`/`A07`) | Bucle monolítico del agente |
| **OpenClaw** (`openclaw/openclaw`) | `ab45e28c` / `v2026.11.10` | `MIT` | Cancelación en cascada, distinción crash vs cancelación, terminales inmutables | Código TypeScript / gateway externo |
| **OpenMausBot** (`milind-soni/OpenMausBot`) | `96ff8445` / `v0.1.180` | `Apache-2.0` + `enterprise/` | Binding `127.0.0.1`, `tini` zombie reaping en `Containerfile`, broker de permisos | **`enterprise/` en cuarentena total** |
| **NanoClaw** (`nanocoai/nanoclaw`) | `9774cb59` / `v2026.11.0` | `MIT` | Allowlist externo de rutas no modificable por el agente en `src/factory/policy.py` | Runtime propio de contenedores |
| **IronClaw** (`nearai/ironclaw`) | `b0b999d9` / `v1.4.1` | `MIT OR Apache-2.0` | Inyección de credenciales solo en frontera de herramienta/egreso; redacción estricta | Runtime Rust |
| **OpenHands** (`OpenHands/OpenHands`) | `adf71d62` / `v1.45.0` | `MIT` | Flujo tipado append-only (`Action` -> `ActionReceipt` / eventos) | Orquestador externo |
| **Playwright / Playwright MCP** | `b0e0b7b5` / `2337aff0` | `Apache-2.0` | **`playwright==1.64.0` incorporado** (`BrowserContext` aislado + perfiles persistentes) | Servidor MCP remoto por defecto |
| **agent-browser** (`vercel-labs/agent-browser`) | `f0a98351` / `v0.44.0` | `Apache-2.0` | Lección documental sobre obsolescencia de refs en DOM dinámico | Dependencia directa |
| **Browser Use** (`browser-use/browser-use`) | `94784c1f` / `1.0.8` | `MIT` | Referencia de comparación | Descartado por acoplamiento LLM-navegador |
| **Cua** (`trycua/cua`) | `848e2a56` / `v0.41.12` | `MIT` | Referencia de interfaz Linux desktop `F12` | Dependencia directa |
| **Munim Computer Use** | `b816c1e5` / `v0.14.2` | `Apache-2.0` | Prioridad AT-SPI sobre coordenadas y separación X11/XWayland vs Wayland | Código externo |
| **CUA-JEV** (`ZJU-REAL/CUA-JEV`) | `eb7ce36e` | `Apache-2.0` | Flujo `Observe -> Guard -> Execute -> Independent Verifier` | Dependencias Windows |

### 3.2 Dependencias incorporadas
- `40` paquetes de terceros fijados en `uv.lock` (`11` directos incl. `pyyaml==6.0.4` + `29` transitivos, todos bajo licencias OSI permisivas documentadas en `THIRD_PARTY_NOTICES.md`).

### 3.3 Resultados medidos (Benchmarks M6 & Fábrica M7)
- **Benchmark comparativo emparejado (`13` escenarios N1/N2 ejecutables; `A11` = `PENDING_N3_LINUX_ENV`)**:
   - **Modo `emulated`** (`make bench`, commit `b567615`):
     - `RuleBasedBaseline`: **`1/13` (`7.7%`)**, `promotion_eligible=False`, `false_positives=3`, `wrong_asset_attributions=3`, `duplicate_effects=1`, `state_loss_count=1`, `isolation_violations=1`, `median=413.90ms`, `p95=433.01ms`.
     - `GrokbotEngine`: **`13/13` (`100.0%`)**, `promotion_eligible=True`, `correct_abstentions=7`, `0` falsos positivos, `0` confusiones de activo, `0` efectos duplicados, `0` pérdida de estado, `0` violaciones de aislamiento, `median=1229.50ms`, `p95=1472.19ms`, `tool_calls=34`, `model_calls=42`, `tokens=3514`, `RAM=79.75 MB`.
     - **Portabilidad `A12` (`lab/configs/facility_b.json`)**: `engine_loc_delta=0`, `adapter_loc_delta=0`, `adaptation_time_seconds=1.234s`, `verified_succeeded=True`.
   - **Modo `local_http` contra servidor mock OpenAI en loopback** (`python -m benchmarks.runner --mode local_http --json`):
     - `GrokbotEngine`: **`13/13` (`100.0%`)**, `model_type="local_http_mock"`, `promotion_eligible=True`, `median=1239.283ms`, `p95=1534.818ms`, `tool_calls=36`, `model_calls=44`, `tokens=3656`, `RAM=80.50 MB`, `A12 verified_succeeded=True`.
   - **Fail-closed con endpoint local inalcanzable** (`--mode local_http --llm-origin http://127.0.0.1:9 --scenarios A08,A09`):
     - Fallo rápido (`status="failed"`, `duration=212.28ms` en `A08` y `60.35ms` en `A09`, `exit_code=1`, cero `TimeoutError` y cero fallback silencioso a emulación).
- **Fábrica de software local M7 (`uv run python -m src.factory.demo --json`)**:
   - **Candidato 1 (`cand-1-index`)**: índice `(canonical_label, area)` sobre repo git lab aislado + `factory.db` WAL aislado -> **`PROMOTED`** (`scan_steps: 100.0 -> 1.0`, `0` confusiones de activo) con `RollbackManifest` y rollback verificado (`HEAD == baseline_commit` y tests post-rollback pasando).
   - **Candidato 2 (`cand-2-skip-area`)**: optimización que omite filtro de `area` -> **`REJECTED`** (`identity_gate_failed`: `wrong_asset_attributions=2`, `area-2=bomba-34-a1` en lugar de `bomba-34-a2`; `final_main_head == promoted_commit` intacto; `LessonRecord` persistido).

---

## 4. Resultados N1, N2, N3 y criterio Linux sin Internet

- **`uv lock --check --offline`**: Exit `0` (`Resolved 41 packages in 4ms`, cero descargas).
- **`make doctor`**: Exit `0` (`n1_ready=True`, `n2_ready=True`, `n3_status=PENDING_N3_LINUX_ENV`).
- **`make lint`**: Exit `0` (`All checks passed!` en `src`, `lab`, `benchmarks`, `deploy`, `tests/unit`, `tests/integration`, `tests/acceptance`).
- **`make typecheck`**: Exit `0` (`Success: no issues found in 99 source files`, `mypy --strict`).
- **`make test-n1`**: Exit `0` (**`120 passed`**).
- **`make test-n2`**: Exit `0` (**`42 passed`**, `0` warnings).
- **`make test-acceptance`**: Exit `0` (**`19 passed`** en `tests/acceptance` con evidencia §6.3 JSONL).
- **`make test-n3`**: Exit `0` (**`2 skipped`** con motivo explícito `PENDING_N3_LINUX_ENV`).
- **`make test-offline`**: Exit `0` (valida `deploy/install_config.yaml`, ejecuta **`23 passed, 20 deselected`** pruebas N1/N2 de `deploy`/loopback/egreso/fábrica + `make test-n3`, e imprime `[PENDING_N3_LINUX_ENV]`).
- **`make check`**: Exit `0` (`doctor` + `lint` + `typecheck` + `test`).
- **`uv run pytest tests/e2e -m tier1 -v`**: Exit `0` (**`99 passed`** en `F01`–`F18`).
- **`uv run pytest tests/e2e -m tier2 -v`**: Exit `0` (**`99 passed`** en `F01`–`F18`).
- **`uv run pytest tests/e2e -m tier3 -v`**: Exit `0` (**`22 passed`** en `T3-01`–`T3-22`).
- **Criterio Linux sin Internet (`A11`)**:
  - Verificado en N2: `validate_local_model_origin`, `ToolRegistry` y `DeployInstallConfig` bloquean orígenes externos (`https://api.openai.com`, `8.8.8.8`, redirecciones HTTP 3xx) antes de conectar; Playwright aborta subrecursos fuera de allowlist y la UI web no realiza peticiones CDN.
  - Pendiente N3 en Linux: aislamiento kernel `ip netns`/`nftables`/`iptables` e inferencia con pesos locales reales (`PENDING_N3_LINUX_ENV`; automatizado en `scripts/verify_n3_linux.sh` y documentado en `deploy/OFFLINE_RUNBOOK.md`).

---

## 5. Inicio de demo reproducible y pasos para reproducir la última falla / bloqueo

### Demos reproducibles
- **Demo industrial Pump 34 (`make demo`)**:
   - Comando: `make demo` (`uv run python -m src.demo`)
   - Resultado observado: `Status: succeeded (ok=True)`, `Backend Mode: emulated`, `N3 Env Status: PENDING_N3_LINUX_ENV`, `ALM-3401` + `WO-3408`, `Receipts: 3 (redaction_clean=True)`, `tool_calls=3, model_calls=4, tokens=288`.
- **Demo fábrica local M7**:
   - Comando: `uv run python -m src.factory.demo --json`
   - Resultado observado: Exit `0`, `"ok": true`, `"rollback_verified": true`, `cand-1-index` promovido (`100.0 -> 1.0`), `cand-2-skip-area` rechazado (`wrong_asset_attributions=2`).
- **Consola Web local**:
   - Comando: `uv run uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 8000` (con `GROKBOT_*` para modo runtime real o sin ellas para stub UI).

### Reproducir los bloqueos y rechazos verificados
- **Bloqueo de entorno N3 en macOS**:
   - `uv run python -m src.n3_probe --strict --json` -> Exit `1` (`"overall_status": "PENDING_N3_LINUX_ENV"`).
   - `./scripts/verify_n3_linux.sh` -> Exit `1` (`[PENDING_N3_LINUX_ENV] Linux host required (detected Darwin)`).
- **Diagnóstico limpio de rollback ante manifiesto inexistente**:
   - `uv run python -m deploy.rollback --manifest /tmp/nonexistent_manifest.json` -> Exit `1`, `stderr`: `Rollback failed: Release manifest not found: /tmp/nonexistent_manifest.json`, cero `"usage:"`.
- **Fallo rápido sin fallback silencioso ante servidor LLM inalcanzable**:
   - `uv run python -m benchmarks.runner --mode local_http --llm-origin http://127.0.0.1:9 --scenarios A08,A09 --json` -> Exit `1`, `A08` & `A09` en `status="failed"` en `<250ms` sin `TimeoutError`.

---

## 6. Horas usadas, recursos observados y riesgo principal

- **Ventana nocturna**: inicio `2026-11-25T09:07:18Z`, cierre M7-T3 `2026-11-25T14:38:00Z` (~`5.51 horas` transcurridas de un presupuesto total de `8.0 horas` hasta `17:07Z`, conservando margen reservado para Tier 4, Tier 5 y reporte final).
- **Recursos observados**: Apple M1 (8 cores), `8 GB` RAM; RSS pico medido en benchmarks `~79.75 MB`; VRAM `N/A` (sin servidor LLM local ni GPU Linux en este host).
- **Riesgo principal**: la ejecución real **N3** en Linux (bloqueo de egreso a nivel kernel `netns`/`iptables`, precisión/latencia/VRAM de un modelo cuantizado real en CPU/GPU local, y sesión AT-SPI/X11/Wayland en vivo) permanece sin validar en hardware Linux hasta disponer del entorno destino, y Tier 4 + Tier 5 de `tests/e2e/` corresponden a las fases siguientes de M7.

---

## 7. Siguiente tarea ejecutable, prerrequisitos y prueba habilitante

- **Siguiente tarea ejecutable inmediata (`B-M7-03`)**:
   - **Objetivo**: Ejecutar y aprobar Tier 4 de la suite `tests/e2e/` y completar el bucle adversarial de cobertura Tier 5.
   - **Prerrequisitos**: Tier 1 (`99/99`), Tier 2 (`99/99`), Tier 3 (`22/22`) E2E y puertas base en `main` (`make check && make test-offline && make test-n3 && make demo && make bench` en Exit `0`).
   - **Prueba habilitante**: `uv run pytest tests/e2e -m tier4 -v` y suite completa `uv run pytest tests/e2e -v`.
- **Siguiente tarea en host Linux destino (`B-N3-01..04`)**:
   - **Objetivo**: Validar N3 completo en Linux sin Internet (`A11` + LLM local real + AT-SPI/X11/Wayland).
   - **Prerrequisitos**: Host Linux provisionado, wheelhouse + Chromium `1248` pre-cacheados, pesos LLM fijados y reglas `netns`/`iptables` activas.
   - **Prueba habilitante**: `./scripts/verify_n3_linux.sh` Exit `0`, `uv run python -m src.n3_probe --strict --json` Exit `0` (`"overall_status": "READY"`) y `make test-n3` pasando `2/2` sin skips.
