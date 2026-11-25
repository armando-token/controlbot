# Comparative Research Index (`F02`)

**Inspection Date**: `2026-11-25T09:13–09:17Z`
**Provenance Policy (Megaplan §3.2 & §3.3)**:
- All 13 external projects below were inspected read-only at verified commits/releases and classified strictly as **Patrón estudiado** (behavioral reference for clean-room Python implementation from independent contracts in `src/contracts/`).
- **Zero** candidate agent framework code is vendored or copy-pasted into `src/`.
- Runtime & dev Python dependencies (**Dependencia incorporada**) are tracked separately in `THIRD_PARTY_NOTICES.md` with exact `uv.lock` versions and SPDX licenses.

---

## Candidate Matrix

| Candidate | Repository | Inspected Commit / Tag | License (Verified) | Primary Role / Verdict | Dossier |
|---|---|---|---|---|---|
| **Rakazo** | `elie222/rakazo` | `bce93a9d7a5c7dee9fa32dd11511b55f8fcb5a81` / `v0.16.0` (testkit: `8b13741378fba0ef91b23223a35bc9a3d0e9e7f0`) | `Apache-2.0` | **Patrón estudiado**: split agent vs computer runtime, fenced DB leases, fresh-snapshot ref check, no effect replay on stream retry, `waiting_takeover` | [rakazo.md](./rakazo.md) |
| **Hermes Agent** | `NousResearch/hermes-agent` | `2fcdbfea1847a1119901835d5970fdca2b3d8ea8` / `v0.23.4` | `MIT` | **Patrón estudiado**: pure `ToolCallGuardrailController`, canonical `(tool, args, result_hash)` successful-repeat & alternating-cycle detection | [hermes-agent.md](./hermes-agent.md) |
| **OpenClaw** | `openclaw/openclaw` | `ab45e28c4d2bb615a90f5cba3331a7a2fe4a6641` / `v2026.11.10` | `MIT` | **Patrón estudiado**: cascading abort, crash vs user-cancel distinction, cross-restart lease liveness, immutable terminals | [openclaw.md](./openclaw.md) |
| **OpenMausBot** | `milind-soni/OpenMausBot` | `96ff844559a1bb07b4d1e555e464db6bfb490f64` / `v0.1.180` | **Mixed**: `Apache-2.0` core + **Proprietary `enterprise/` carve-out** | **Patrón estudiado** (core concepts only; **`enterprise/` quarantined**): `127.0.0.1` loopback binding, trusted-proxy check, `init` zombie reaping, permission broker | [openmausbot.md](./openmausbot.md) |
| **NanoClaw** | `nanocoai/nanoclaw` | `9774cb596a32039d9464d78174ec5ed9531a9898` / `v2026.11.0` | `MIT` | **Patrón estudiado**: external non-agent-modifiable mount allowlist & read-only host mounts for M7 software factory | [sandboxes-and-isolation.md](./sandboxes-and-isolation.md) |
| **IronClaw** | `nearai/ironclaw` | `b0b999d96781516ee05e6ba961d6f3ead900da96` / `ironclaw-v1.4.1` | Dual `MIT OR Apache-2.0` | **Patrón estudiado**: secrets never enter LLM context; injected only at egress/tool boundary | [sandboxes-and-isolation.md](./sandboxes-and-isolation.md) |
| **OpenHands** | `OpenHands/OpenHands` | `adf71d626b81a0db00902e0d3edf2b00d2cf917c` / `v1.45.0` | `MIT` | **Patrón estudiado**: typed append-only event stream (`Action` -> `Observation`) for engine & M7 factory | [sandboxes-and-isolation.md](./sandboxes-and-isolation.md) |
| **Playwright & Playwright MCP** | `microsoft/playwright`, `microsoft/playwright-mcp` | `b0e0b7b555e637cc8c0ce94dd98c3be153861333` (`v1.65.1`) / `2337aff0213d28db41d3e3daf48cee19b3d0bd82` (`v0.0.86`) | `Apache-2.0` (Chromium: `BSD-3-Clause`; FFmpeg: `LGPL-2.1+`) | **Dependencia incorporada** (`playwright==1.64.0` matching cached `chromium-1248`): isolated `BrowserContext`, persistent profiles, semantic locators | [browser-automation.md](./browser-automation.md) |
| **agent-browser** | `vercel-labs/agent-browser` | `f0a98351ec920bd826b22c98dacf8414f04b9832` / `v0.44.0` | `Apache-2.0` | **Patrón estudiado** (and discarded as dependency): compact accessibility refs; documented ref-staleness hazard | [browser-automation.md](./browser-automation.md) |
| **Browser Use** | `browser-use/browser-use` | `94784c1f7ecb6b0a5f565b7f9fba59e395b7e048` / `1.0.8` | `MIT` | **Discarded as dependency**: opaque LLM-browser loop coupling | [browser-automation.md](./browser-automation.md) |
| **Cua** | `trycua/cua` | `848e2a561a5f8b01286d855afb58bc1ac19a150c` / `cua-spaces-v0.41.12` | `MIT` (`LICENSE.md`) | **Reference for M4/M5 Linux desktop probe (`F12`)** behind `src/adapters/` | [desktop-at-spi.md](./desktop-at-spi.md) |
| **Munim Computer Use** | `munimtechnologies/munim-computer-use` | `b816c1e5d3f40e4e47cef96f9cad52e6ae10e0a9` / `v0.14.2` | `Apache-2.0` | **Patrón estudiado** for `F12`: AT-SPI element actions first, explicit X11/XWayland vs native Wayland geometry separation | [desktop-at-spi.md](./desktop-at-spi.md) |
| **CUA-JEV** | `ZJU-REAL/CUA-JEV` | `eb7ce36e541d92b44c4cf0573334294fd40569d5` (no GitHub Release tag) | `Apache-2.0` (`LICENSE` & `pyproject.toml`; GitHub API returns `NOASSERTION`) | **Patrón estudiado** (Windows deps discarded): `Observe -> Legal ActionCandidate -> ActionGuard -> Execute -> Independent Verifier` | [desktop-at-spi.md](./desktop-at-spi.md) |

---

## Core Design Synthesis for Grokbot-clon

1. **Runtime & State Isolation (`Rakazo`, `IronClaw`, `OpenHands`)**: Keep coordinator/LLM runtime strictly separated from browser/adapter execution (`src/engine/` vs `src/adapters/`). Persist typed append-only receipts and events in SQLite WAL; never allow secrets into LLM context or `ActionReceipt`s (`ActionReceipt` enforces fail-closed redaction in M1).
2. **Loop & Budget Control (`Hermes Agent`, `OpenClaw`)**: Combine Hermes's side-effect-free `(tool, canonical_args, result_hash)` repeat/alternating-cycle detection (`A06`, `A07`) with SQLite WAL persistence across restarts (`A14`), root-shared hierarchical budgets (`depth=1`, `2` active children), and OpenClaw's cascading cancellation + cross-process lease liveness checks (`A09`).
3. **Browser & Industrial Verification (`Playwright`, `Rakazo`, `CUA-JEV`)**: Use Playwright Python (`1.64.0`) with isolated `BrowserContext` + dedicated OS profile directories per `(user_id, profile_id, app_id)`, enforce origin allowlists outside the LLM, verify fresh DOM/asset state right before and after actions, and preserve contradictions (`A13`) rather than merging conflicting claims.
4. **Linux Desktop Probe (`Munim`, `Cua`)**: Prefer AT-SPI element actions over coordinate clicks, explicitly distinguish X11/XWayland vs native Wayland capabilities, and report `PENDING_N3_LINUX_ENV` honestly on macOS.
