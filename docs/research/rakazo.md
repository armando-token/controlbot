# Candidate Analysis: Rakazo

- **Classification**: **Patrón estudiado** (behavioral reference only; zero code vendored)
- **Owner & Repository**: `elie222` (Elie Steinbock) · `https://github.com/elie222/rakazo`
- **Verified Provenance (inspected `2026-11-25T09:13–09:17Z`)**:
  - `main` HEAD: `bce93a9d7a5c7dee9fa32dd11511b55f8fcb5a81` (`2026-11-25T08:58:51Z`)
  - Latest Release: `v0.16.0` (`2026-11-24T16:05:41Z`)
  - Megaplan-pinned testkit commit (Megaplan line 86, 351): `8b13741378fba0ef91b23223a35bc9a3d0e9e7f0`
- **License**: `Apache-2.0` (`LICENSE` and `NOTICE` verified at repo root; GitHub API `spdx_id=Apache-2.0`).
- **Platform & Dependencies**: TypeScript / Node.js, React 19, Electron, Expo, PostgreSQL, Prisma, Graphile Worker, Docker/cloud sandboxes (E2B, Daytona, Boat), X11 Linux desktop container + Chrome.

---

## Verified Mechanisms, Files & Symbols

1. **Runtime Separation (`docs/computer-runtime.md`)**:
   - Separates the agent runtime (`Pi` running in the API/worker process) from the computer runtime (`SandboxProvider`: Docker, E2B, Daytona, Boat, `desktop/fake`).
   - Distinguishes **Team Computers** (bots sharing one workspace/OS user under `bots/<bot-id>/` and `shared/`, explicitly documented as *not security boundaries*) from **Private Computers** (full workspace isolation per bot).
   - Each active Team bot receives its own X display, Chrome process, and persistent Chrome profile keyed to the bot ID; concurrency is guarded via fenced per-bot DB leases.

2. **Browser Health, Fresh-Snapshot Verification & Secret Boundary (`docs/computer-runtime.md`)**:
   - Every screen read/tool verifies Chrome DevTools responsiveness within `2s`; 3 consecutive hangs restart Chrome (`computer.browser_restarted`), rate-limited to once per 10 minutes before raising `computer.screen_not_ready`.
   - Wraps `agent-browser` via a helper that re-validates every element ref against a fresh snapshot immediately before acting (mitigating stale-ref misclicks onto replacement elements or other pages).
   - Keeps navigation allowlists and `page_secrets.py` credential injection outside `agent-browser` (isolated world over CDP).

3. **Human Takeover & Effect-Safe Recovery (`docs/computer-runtime.md`, `packages/testkit/src/runtime/pi-offline.test.ts` at `8b13741378fba0ef91b23223a35bc9a3d0e9e7f0` L56–612)**:
   - `waiting_takeover` pins model + connection/auth; HTTP `409 ("Stop the bot first")` rejects takeover while the bot holds a live execution lease unless in `waiting_takeover`; `COMPUTER_TAKEOVER_TTL_MS` defaults to 15 minutes.
   - `MODEL_STREAM_MAX_RETRIES` (`0–5`); reconciler quarantines ambiguous save/teardown states (`Recover`/`Update`/`Reset`) without replaying uncertain/completed effects.
   - `pi-offline.test.ts` (`PiAgentRuntime`, `startModelEmulator`, `ModelEmulatorRequest`) explicitly tests `"retries a dropped stream and an overloaded provider after tool work without replaying the effect"` (L57) and `"uses the same context policy for separate parent and subagent runs"` (L322).

---

## Engineering Verdict for Grokbot-clon

- **Adopt Conceptually**:
  - Strict separation between coordinator/engine (`src/engine/`) and browser/OS execution (`src/adapters/`).
  - Fenced per-step/per-session DB leases rejecting late results (`lease_generation`).
  - Per-`(user_id, profile_id, app_id)` persistent browser profiles (`F10`, `A05`).
  - Fresh-snapshot validation immediately before DOM actions and keeping domain allowlists + secret injection outside the LLM and browser helper.
  - Lease-protected human takeover (`409 Conflict` when active lease exists) and no automatic replay of uncertain/completed side effects (`A08`, `A10`).
  - Offline deterministic `EmulatedModelClient` harness modeled on `ModelEmulator` (`F09`, `M2`).
- **Discard**:
  - TypeScript/Node.js/PostgreSQL/Prisma/Graphile Worker stack (Grokbot-clon uses a Python 3.12 + SQLite WAL modular monolith per `ADR-0001` and `ADR-0002`).
  - Cloud sandbox providers (E2B, Daytona, Boat) — incompatible with internet-blocked local Linux LAN.
  - Team Computer shared-OS-user workspace model — insufficient trust-boundary isolation across industrial profiles/apps.
