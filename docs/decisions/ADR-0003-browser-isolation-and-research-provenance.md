# ADR-0003: Playwright Browser Isolation & Clean-Room Research Provenance

- **Status**: Accepted (M1)
- **Date**: 2026-11-25
- **Owner**: Investigación y procedencia + Orquestador (`teamwork_worker_m1_1`)
- **Governing Specification**: `MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md` (§3.1–§3.3, §4.1, §4.3, §4.5, §6.1 `A05`/`A10`/`A11`)

---

## Context
Grokbot-clon must interact with independent simulated industrial web applications (SCADA, Maintenance, EffectSim) with strict identity/cookie isolation (`A05`), human takeover / auth expiry pause-resume (`A10`), outbound-blocked LAN compatibility (`A11`), and defensible clean-room IP/license provenance across 13 surveyed repositories (`docs/research/`).

## Decision
1. **Clean-Room Provenance & Quarantine Policy (Megaplan §3.2–§3.3)**:
   - All 13 external candidates (`Rakazo`, `Hermes Agent`, `OpenClaw`, `OpenMausBot`, `NanoClaw`, `IronClaw`, `OpenHands`, `Playwright`, `Playwright MCP`, `agent-browser`, `Browser Use`, `Cua`, `Munim Computer Use`, `CUA-JEV`) were verified at exact commits/releases on `2026-11-25` and classified strictly as **Patrón estudiado** (behavioral specification only).
   - **Zero** candidate agent framework code is vendored or translated into `src/`.
   - **Explicit Quarantine**:
     - `milind-soni/OpenMausBot/enterprise/` is source-available under the proprietary `OpenMausBot Enterprise License` (paid/partner key carve-out) — strictly quarantined and unused.
     - `ZJU-REAL/CUA-JEV` triggers GitHub `NOASSERTION` via API (though raw `LICENSE` / `pyproject.toml` are `Apache-2.0`) and targets Windows (`pywin32`/`pywinauto`) — behavioral loop adopted conceptually, implementation discarded.
     - Node/TS (`Rakazo`, `OpenClaw`, `NanoClaw`, `OpenMausBot`) and Rust (`IronClaw`, `Munim`, `agent-browser`) runtimes are excluded from MVP dependencies to keep an auditable single-runtime Python deployment on offline Linux.
   - Only permissive OSI-licensed Python packages (`MIT`, `BSD-3-Clause`, `Apache-2.0`, `ISC`, `MPL-2.0` if any — verified in `THIRD_PARTY_NOTICES.md`) are incorporated via `uv.lock`.
2. **Primary Browser Execution Dependency (`Dependencia incorporada`)**:
   - Adopt `playwright==1.64.0` (`Apache-2.0`, matching host-cached `chromium-1248`) with semantic/DOM/ARIA locators (`get_by_role`, `get_by_label`, `get_by_text`) first.
   - Keep `Playwright MCP` as an optional interoperable pattern behind `ToolSpec`/`ToolRegistry`, not a mandatory external server process.
   - Discard `agent-browser` (separate Rust CLI over CDP with documented ref-staleness hazard in Rakazo `docs/computer-runtime.md`) and `Browser Use` (couples LLM directly into browser loop).
3. **Hard Browser & Session Isolation Invariants**:
   - **Strict Per-Identity Contexts**: Each `(user_id, profile_id, app_id)` receives a dedicated isolated `BrowserContext` and OS profile directory — never share cookies/localStorage across profiles or apps (avoiding Rakazo's shared-OS-user Team Computer trust flaw).
   - **Allowlists & Secrets Outside LLM**: Origin allowlists (`TaskScope.allowed_origins`, `ToolSpec.allowed_origins`) and credential injection live exclusively in `ToolRegistry` / adapters; secrets never enter LLM prompts or `ActionReceipt`s (`IronClaw`/`Rakazo` pattern, enforced by `src/contracts/redaction.py`).
   - **Freshness & Identity Guard**: Adapters re-verify fresh DOM/asset identity immediately before and after actions (`CUA-JEV` / `Rakazo` pattern).
   - **Mutual-Exclusion Human Takeover**: Human takeover (`waiting_for_input`) locks out automated Playwright actions on that `session_id` until explicit release, while active execution leases reject takeover requests (`409 Conflict`).

## Alternatives Considered
1. **Using `agent-browser` or `Browser Use`**: Rejected due to mixed Rust/CDP ref-staleness risk and loss of deterministic verification / budget accounting.
2. **Shared browser process with tab separation**: Rejected; tabs in one context share cookies/storage and fail `A05` isolation across concurrent identities.
3. **Vendoring third-party agent guardrails or orchestrators**: Rejected per Megaplan §1 & §3.3 clean-room design and license quarantine rules.

## Consequences
- **Positive**: Clean OSI licensing (`MIT` / `BSD-3-Clause` / `Apache-2.0`), deterministic Playwright context isolation, zero CDP ref-staleness surprises, and unambiguous license provenance in `THIRD_PARTY_NOTICES.md`.
- **Negative / Trade-offs**: Playwright browser binaries (`Chromium` under `BSD-3-Clause` + notices, optional `FFmpeg` under `LGPL-2.1+`) must be pre-cached and documented for air-gapped M8 packaging.

## Revocation Conditions
- Revisit Playwright or add a secondary adapter behind `src/adapters/` only if M5/M6 benchmarks demonstrate unresolvable opaque-DOM failures where Linux AT-SPI (`F12`, `Munim`/`Cua` pattern) or Playwright MCP yields measurably higher verified accuracy without violating isolation or offline Linux constraints.
