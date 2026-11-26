# NIGHT_REPORT — Grokbot-clon

## Estado verificable y siguiente acción
- **Estado del producto**: **`flujo con emulador`**
- **Estado general de cierre M0–M7**: **M1–M7 COMPLETO Y VERIFICADO en N1 + N2 (Darwin ARM64)** + **ControlBot Studio UX claro (`/app`) estilo Rakazo (Navegador Playwright en vivo + Terminal PTY + Explorador de archivos + 23 modelos `agy` dinámicos), servidor ligero (`make server` / `launchd`) y app nativa macOS Xcode (`macos/ControlBotApp/`)** sobre `main` (`72497bc5f9df2ea5804917230460cc6789b79f60`); **`M8_CAPSTONE` = `PAUSED / DEFERRED`** por instrucción explícita del usuario (`2026-11-25T21:31:15Z`, blueprints `c7b61f5c` y `5d5e2b7b` preservados para reanudar bajo demanda); **N3 Linux (`A11` kernel `netns`/`iptables`, LLM local con pesos reales y AT-SPI/X11/Wayland) = `PENDING_N3_LINUX_ENV`**.
- **Siguiente acción ejecutable**: **Probar el software M1–M7 inmediatamente** (ver **Sección 8: Guía Rápida / Quickstart** abajo), completar **Sentinel Victory Audit** de cierre M1–M7 y ejecutar validación **N3** en host Linux destino (`./scripts/verify_n3_linux.sh`).

---

## 1. Commit / Punto de recuperación y entorno ejecutado

- **Rama activa**: `main`
- **Commit de código y pruebas más reciente**: `72497bc5f9df2ea5804917230460cc6789b79f60` (`feat(studio): add Rakazo-style live browser/PTY terminal/files workspace & dynamic agy models`)
- **Commit anterior Studio UX + servicio headless**: `64a0bf9a834211e3d9fb30505e98c0dbd15e35d3` (`feat(studio,macos): light mode, multi-project workspace, agy resume, hidden plant & headless service`)
- **Commit anterior Studio UX + Xcode**: `70cafa363589f055d68cbaee1a3474a2e1890507` (`feat(ui,macos): add ControlBot Studio UX (/app), unified local server & Xcode macOS app`)
- **Commit de código y pruebas M7-T5 (R5) verificado**: `70ed485340f2bb8729c0a97649a5572a3aba5c79` (`fix(m7-t5): clear stale WAITING_FOR_INPUT result_json across cancel, wait-timeout, and resume (T5-25)`)
- **Commit de backlog/gobernanza más reciente (no-reporte)**: `51ac97878f518fbe576f25830e5d330a5e7c46c0` (`docs(ops): refresh NIGHT_STATE and BACKLOG for M7-T5-R5 commit 70ed485`)
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
  - `4a26c28` — `docs(night-report): update NIGHT_REPORT with M7-T3-R4 commit SHA b567615 and verification counts`
  - `2a7da5a` — `fix(m7-t3): enforce -p1 diff prefixes, symlink rename checks & NFC/NFD normalization`
  - `655d988` — `docs(night-report): update NIGHT_REPORT with M7-T3-R5 commit SHA 2a7da5a and verification counts`
  - `a072414` — `fix(m7-t3): close binary diff headers, 120000 binary patch & null-byte edge cases`
  - `4c4f39c` — `docs(night-report): update NIGHT_REPORT with M7-T3-R5 commit SHA a072414 and verification counts`
  - `08687e0` — `fix(m7-t3): close binary patch leak, cross-section symlink, space timestamp & short case-fold gaps`
  - `2cc9384` — `docs(night-report): update NIGHT_REPORT with M7-T3-R6 commit SHA 08687e0 and verification counts`
  - `3ea788a` — `fix(m7-t4): resolve T4-02 multi-resume disambiguation, T4-03 lab cookie restart & T4-10 deploy.n3_probe`
  - `0a59301` — `docs(night-report): update NIGHT_REPORT with M7-T4 commit SHA 3ea788a and verification counts`
  - `2e66e49` — `fix(m7-t4): remove unconditional pre-tool area pause in runtime turn factory (Option 2)`
  - `813357a` — `docs(night-report): update NIGHT_REPORT with final M7-T4 commit SHA 2e66e49 and verification counts`
  - `869ebec` — `fix(m7-t4): share asset_id-aware area resolution in build_industrial_result_verifier`
  - `3c3a577` — `docs(night-report): update NIGHT_REPORT with M7-T4-R2 commit SHA 869ebec and verification counts`
  - `d0367b6` — `fix(m7-t5): resolve all 21 Tier 5 adversarial gaps and add @pytest.mark.tier5 coverage`
  - `f238ad5` — `docs(night-report): update NIGHT_REPORT and release manifest for M7-T5 commit d0367b6`
  - `4845c82` — `fix(m7-t5): address R1 reviewer findings (zero-obs FAILED, empty GROKBOT_ALLOWED_ORIGINS, combined awaitable timeout)`
  - `af61d52` — `docs(backlog): mark M7-T5 done and pause/defer M8_CAPSTONE per user request`
  - `840be43` — `docs(night-report): update NIGHT_REPORT, M8_CAPSTONE pause note, and Quickstart for M7-T5 commit 4845c82`
  - `6c0146c` — `fix(m7-t5): block .git internals in factory and fail waiting children on parent wait timeout (T5-22, T5-23)`
  - `5388d3a` — `docs(ops): refresh NIGHT_STATE and BACKLOG for M7-T5-R3 commit 6c0146c`
  - `3e983ad` — `docs(night-report): update NIGHT_REPORT for M7-T5-R3 commit 6c0146c and NIGHT_STATE 5388d3a`
  - `7182aee` — `fix(m7-t5): eliminate overlapping parent/child human wait accounting and handle child wait timeout (T5-24)`
  - `f1e41d3` — `docs(ops): refresh NIGHT_STATE and BACKLOG for M7-T5-R4 commit 7182aee`
  - `cf3e78d` — `docs(night-report): update NIGHT_REPORT for M7-T5-R4 commit 7182aee and NIGHT_STATE f1e41d3`
  - `70ed485` — `fix(m7-t5): clear stale WAITING_FOR_INPUT result_json across cancel, wait-timeout, and resume (T5-25)`
  - `51ac978` — `docs(ops): refresh NIGHT_STATE and BACKLOG for M7-T5-R5 commit 70ed485`
  - `6d3e266` — `docs(night-report): update NIGHT_REPORT for M7-T5-R5 commit 70ed485 and NIGHT_STATE 51ac978`
  - `70cafa3` — `feat(ui,macos): add ControlBot Studio UX (/app), unified local server & Xcode macOS app`
  - `37fc040` — `docs(night-report): update NIGHT_REPORT for ControlBot Studio UX & macOS app commit 70cafa3`
  - `64a0bf9` — `feat(studio,macos): light mode, multi-project workspace, agy resume, hidden plant & headless service`
  - `b8c0a37` — `docs(night-report): update NIGHT_REPORT for light-mode studio, agy continuity & headless service commit 64a0bf9`
  - `72497bc` — `feat(studio): add Rakazo-style live browser/PTY terminal/files workspace & dynamic agy models`
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
| **M7 (E2E Tiers 1–4 + Tier 5)** | `DONE` | Tier 1 (`99/99`), Tier 2 (`99/99`), Tier 3 (`22/22`), Tier 4 (`10/10`, `230/230` acumulado) y Tier 5 Adversarial Hardening (`30/30` `@pytest.mark.tier5` cubriendo `T5-01`..`T5-25` + hallazgos R1/R2/R3/R4/R5) verificados en `main` (`70ed485`) |
| **M8_CAPSTONE** (`AntigravityCliModelClient`, ArtCraft Office `.xlsx`/`.docx`, 3er portal) | `PAUSED / DEFERRED` | Pausado por instrucción del usuario (`2026-11-25T21:31:15Z`) para probar M1–M7 de inmediato; planos técnicos `c7b61f5c` y `5d5e2b7b` listos para reanudar bajo petición |
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
| **Munim Computer Use** | `b816c1e5` / `0.14.2` | `Apache-2.0` | Prioridad AT-SPI sobre coordenadas y separación X11/XWayland vs Wayland | Código externo |
| **CUA-JEV** (`ZJU-REAL/CUA-JEV`) | `eb7ce36e` | `Apache-2.0` | Flujo `Observe -> Guard -> Execute -> Independent Verifier` | Dependencias Windows |

### 3.2 Dependencias incorporadas
- `40` paquetes de terceros fijados en `uv.lock` (`11` directos incl. `pyyaml==6.0.4` + `29` transitivos, todos bajo licencias OSI permisivas documentadas en `THIRD_PARTY_NOTICES.md`).

### 3.3 Resultados medidos (Benchmarks M6 & Fábrica M7)
- **Benchmark comparativo emparejado (`13` escenarios N1/N2 ejecutables; `A11` = `PENDING_N3_LINUX_ENV`)**:
   - **Modo `emulated`** (`make bench`, código `70ed485`):
     - `RuleBasedBaseline`: **`1/13` (`7.7%`)**, `promotion_eligible=False`, `false_positives=3`, `wrong_asset_attributions=3`, `duplicate_effects=1`, `state_loss_count=1`, `isolation_violations=1`, `median=414.16ms`, `p95=431.53ms`.
     - `GrokbotEngine`: **`13/13` (`100.0%`)**, `promotion_eligible=True`, `correct_abstentions=7`, `0` falsos positivos, `0` confusiones de activo, `0` efectos duplicados, `0` pérdida de estado, `0` violaciones de aislamiento, `median=1234.21ms`, `p95=1473.74ms`, `tool_calls=37`, `model_calls=45`, `tokens=3730`, `RAM=81.14 MB`.
     - **Portabilidad `A12` (`lab/configs/facility_b.json`)**: `engine_loc_delta=0`, `adapter_loc_delta=0`, `adaptation_time_seconds=1.237s`, `verified_succeeded=True`.
   - **Modo `local_http` contra servidor mock OpenAI en loopback** (`uv run python -m benchmarks.runner --mode local_http --json`):
     - `GrokbotEngine`: **`13/13` (`100.0%`)**, `model_type="local_http_mock"`, `promotion_eligible=True`, `median=1223.992ms`, `p95=1511.524ms`, `tool_calls=35`, `model_calls=43`, `tokens=3586`, `RAM=82.12 MB`, `A12=1.224s (verified_succeeded=True)`.
   - **Fail-closed con endpoint local inalcanzable** (`--mode local_http --llm-origin http://127.0.0.1:9 --scenarios A08,A09`):
     - Fallo rápido (`status="failed"`, `exit_code=1`, cero `TimeoutError` y cero fallback silencioso a emulación).
- **Fábrica de software local M7 (`uv run python -m src.factory.demo --json`)**:
   - **Candidato 1 (`cand-1-index`)**: índice `(canonical_label, area)` sobre repo git lab aislado + `factory.db` WAL aislado -> **`PROMOTED`** (`scan_steps: 100.0 -> 1.0`, `0` confusiones de activo) con `RollbackManifest` y rollback verificado (`HEAD == baseline_commit` y tests post-rollback pasando).
   - **Candidato 2 (`cand-2-skip-area`)**: optimización que omite filtro de `area` -> **`REJECTED`** (`identity_gate_failed`: `wrong_asset_attributions=2`, `area-2=bomba-34-a1` en lugar de `bomba-34-a2`; `final_main_head == promoted_commit` intacto; `LessonRecord` persistido).

---

## 4. Resultados N1, N2, N3 y criterio Linux sin Internet

- **`uv lock --check --offline`**: Exit `0` (`Resolved 41 packages in 3ms`, cero descargas).
- **`make doctor`**: Exit `0` (`n1_ready=True`, `n2_ready=True`, `n3_status=PENDING_N3_LINUX_ENV`).
- **`make lint`**: Exit `0` (`All checks passed!` en `src`, `lab`, `benchmarks`, `deploy`, `tests/unit`, `tests/integration`, `tests/acceptance`; `uv run ruff check .` también Exit `0`).
- **`make typecheck`**: Exit `0` (`Success: no issues found in 105 source files`, `mypy --strict`).
- **`make test-n1`**: Exit `0` (**`150 passed`**).
- **`make test-n2`**: Exit `0` (**`53 passed, 3 deselected`**).
- **`make test-acceptance`**: Exit `0` (**`19 passed, 2 deselected`** en `tests/acceptance` con evidencia §6.3 JSONL).
- **`make test-n3`**: Exit `0` (**`2 skipped`** con motivo explícito `PENDING_N3_LINUX_ENV`).
- **`make test-offline`**: Exit `0` (valida `deploy/install_config.yaml`, ejecuta **`26 passed, 20 deselected`** pruebas N1/N2 de `deploy`/loopback/egreso/fábrica + `make test-n3`, e imprime `[PENDING_N3_LINUX_ENV]`).
- **`make check`**: Exit `0` (`doctor` + `lint` + `typecheck` + `test`).
- **`uv run pytest tests/e2e -m tier1 -v`**: Exit `0` (**`99 passed`** en `F01`–`F18`).
- **`uv run pytest tests/e2e -m tier2 -v`**: Exit `0` (**`99 passed`** en `F01`–`F18`).
- **`uv run pytest tests/e2e -m tier3 -v`**: Exit `0` (**`22 passed`** en `T3-01`–`T3-22`).
- **`uv run pytest tests/e2e -m tier4 -v`**: Exit `0` (**`10 passed`** en `T4-01`–`T4-10`; **`230/230`** E2E completo).
- **`uv run pytest -m tier5 -v`**: Exit `0` (**`30 passed, 421 deselected`** pruebas adversariales de caja blanca `T5-01`–`T5-25` + hallazgos R1/R2/R3/R4/R5).
- **`deploy/release_manifest.json`**: regenerado sobre `70ed485` (`rel-0.1.0-70ed4853-20261125T235149Z`, **`71`** artefactos verificados por SHA-256 con `0` discrepancias, `n3_status=PENDING_N3_LINUX_ENV`).
- **Criterio Linux sin Internet (`A11`)**:
  - Verificado en N2: `validate_local_model_origin`, `ToolRegistry` y `DeployInstallConfig` bloquean orígenes externos (`https://api.openai.com`, `8.8.8.8`, redirecciones HTTP 3xx) antes de conectar; Playwright aborta subrecursos fuera de allowlist y la UI web no realiza peticiones CDN.
  - Pendiente N3 en Linux: aislamiento kernel `ip netns`/`nftables`/`iptables` e inferencia con pesos locales reales (`PENDING_N3_LINUX_ENV`; automatizado en `scripts/verify_n3_linux.sh` y documentado en `deploy/OFFLINE_RUNBOOK.md`).

---

## 5. Inicio de demo reproducible y pasos para reproducir la última falla / bloqueo

### Demos reproducibles
- **Demo industrial Pump 34 (`make demo`)**:
   - Comando: `make demo` (`uv run python -m src.demo`)
   - Resultado observado: `Run ID: run-9074af32cb8e`, `Status: succeeded (ok=True)`, `Backend Mode: emulated`, `N3 Env Status: PENDING_N3_LINUX_ENV`, `ALM-3401` + `WO-3408`, `Receipts: 3 (redaction_clean=True)`, `tool_calls=3, model_calls=4, tokens=288`.
- **Demo fábrica local M7**:
   - Comando: `uv run python -m src.factory.demo --json`
   - Resultado observado: Exit `0`, `"ok": true`, `"rollback_verified": true`, `cand-1-index` promovido (`100.0 -> 1.0`), `cand-2-skip-area` rechazado (`wrong_asset_attributions=2`).
- **Consola Web local interactiva**:
   - Ver **Sección 8 (Quickstart)** para lanzar las 3 apps sintéticas (`lab.scada_app`, `lab.maintenance_app`, `lab.effect_sim`) y la consola web ControlBot (`http://127.0.0.1:8000`).

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

- **Ventana nocturna**: inicio `2026-11-25T09:07:18Z`, cierre M7-T5-R5 `2026-11-26T00:06:00Z` (~`14.98 horas` acumuladas entre M0–M7 completando el Megaplan original; `M8_CAPSTONE` pausado/diferido por petición del usuario).
- **Recursos observados**: Apple M1 (8 cores), `8 GB` RAM; RSS pico medido en benchmarks `~82.12 MB`; VRAM `N/A` (sin servidor LLM local ni GPU Linux en este host).
- **Riesgo principal**: la ejecución real **N3** en Linux (bloqueo de egreso a nivel kernel `netns`/`iptables`, precisión/latencia/VRAM de un modelo cuantizado real en CPU/GPU local, y sesión AT-SPI/X11/Wayland en vivo) permanece sin validar en hardware Linux (`PENDING_N3_LINUX_ENV`) hasta disponer del entorno destino.

---

## 7. Siguiente tarea ejecutable, prerrequisitos y prueba habilitante

- **Entrega lista para el usuario (M1–M7 completo)**:
   - **Objetivo**: Probar ControlBot M1–M7 localmente (`make demo`, `make bench`, consola Web + apps `lab/`) y finalizar el Sentinel Victory Audit sobre `main` (`70ed485` / `51ac978`). `M8_CAPSTONE` permanece `PAUSED / DEFERRED` (`c7b61f5c`, `5d5e2b7b`) hasta nueva solicitud del usuario.
   - **Prerrequisitos**: `.venv` + Chromium `1248` instalados (verificados por `make doctor`).
   - **Prueba habilitante**: `make check && make test-offline && make test-n3 && make demo && make bench` + `uv run pytest tests/e2e -v` (`230/230`) + `uv run pytest -m tier5 -v` (`30/30`).
- **Siguiente tarea en host Linux destino (`B-N3-01..04`)**:
   - **Objetivo**: Validar N3 completo en Linux sin Internet (`A11` + LLM local real + AT-SPI/X11/Wayland).
   - **Prerrequisitos**: Host Linux provisionado, wheelhouse + Chromium `1248` pre-cacheados, pesos LLM fijados y reglas `netns`/`iptables` activas.
   - **Prueba habilitante**: `./scripts/verify_n3_linux.sh` Exit `0`, `uv run python -m src.n3_probe --strict --json` Exit `0` (`"overall_status": "READY"`) y `make test-n3` pasando `2/2` sin skips.

---

## 8. Guía Rápida de Uso y Verificación (Quickstart)

### 8.1 Verificación automática rápida (todo local, sin descargas)
```bash
cd /Users/armandosilva/Projects/Grokbotclon

make check          # doctor + ruff + mypy --strict + unit/integration/acceptance (N1/N2)
make demo           # Demo completo Pump 34 (SCADA + Maintenance + Playwright + SQLite WAL)
make bench          # Benchmark comparativo (RuleBasedBaseline vs GrokbotEngine, 13 escenarios)
make test-offline   # Validación offline deploy/ + loopback/egreso + fábrica M7 (+ estado N3)
```

### 8.2 Lanzar las aplicaciones de laboratorio + Consola Web de ControlBot (1 comando o App macOS)
- **Servicio headless ligero (`launchd` / `make server`)**:
  ```bash
  ./scripts/install_macos_service.sh install        # loopback 127.0.0.1:8000 (--no-lab)
  ./scripts/install_macos_service.sh install --lan  # Wi-Fi LAN 0.0.0.0:8000 (--no-lab)
  make server                                       # ejecución manual ligera sin lab
  ```
- **App nativa macOS (`Xcode` / `ControlBot.app`)**:
  ```bash
  open /Users/armandosilva/Projects/Grokbotclon/macos/build/ControlBot.app
  # O abrir en Xcode IDE: open /Users/armandosilva/Projects/Grokbotclon/macos/ControlBotApp/ControlBot.xcodeproj
  ```
- **Launcher completo con portales de planta (`make ui`)**:
  ```bash
  make ui
  # Abre http://127.0.0.1:8000/app (ControlBot Studio UX) o http://127.0.0.1:8000/ (Consola Clásica)
  ```

O bien en terminales separadas desde `/Users/armandosilva/Projects/Grokbotclon`:

1. **Terminal 1 — Lab SCADA (`127.0.0.1:8101`)**:
   ```bash
   uv run uvicorn lab.scada_app:create_scada_app --factory --host 127.0.0.1 --port 8101
   ```
2. **Terminal 2 — Lab Maintenance (`127.0.0.1:8102`)**:
   ```bash
   uv run uvicorn lab.maintenance_app:create_maintenance_app --factory --host 127.0.0.1 --port 8102
   ```
3. **Terminal 3 — Lab EffectSim (`127.0.0.1:8103`, opcional para pruebas con efectos)**:
   ```bash
   uv run uvicorn lab.effect_sim:create_effect_sim_app --factory --host 127.0.0.1 --port 8103
   ```
4. **Terminal 4 — Consola Web ControlBot (`http://127.0.0.1:8000`)**:
   ```bash
   GROKBOT_INSTALLATION_CONFIG=lab/configs/facility_a.json \
   GROKBOT_DB_PATH=var/grokbot_ui.sqlite3 \
   GROKBOT_PROFILE_ROOT=.browser_profiles/ui \
   uv run uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 8000
   ```
5. Abrir **`http://127.0.0.1:8000`** en el navegador y enviar una consulta, por ejemplo:
   - `¿Qué alarma apareció primero en la bomba 34?` (en `allowed_origins`: `http://127.0.0.1:8101,http://127.0.0.1:8102`; sin `allowed_areas` para probar la pausa por ambigüedad multi-área y reanudación manual con `area-1`, o con `allowed_areas`: `area-1` para ejecución directa).
   - Nota de entorno: en macOS (`Darwin`), `N3` (`netns`/`iptables`, pesos LLM locales y `AT-SPI`) permanece honestamente marcado como `PENDING_N3_LINUX_ENV`.
