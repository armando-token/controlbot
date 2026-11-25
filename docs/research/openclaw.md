# Candidate Analysis: OpenClaw

- **Classification**: **Patrón estudiado** (behavioral reference only; zero code vendored)
- **Owner & Repository**: `openclaw` · `https://github.com/openclaw/openclaw`
- **Verified Provenance (inspected `2026-11-25T09:13–09:17Z`)**:
  - `main` HEAD: `ab45e28c4d2bb615a90f5cba3331a7a2fe4a6641` (`2026-11-25T09:06:25Z`)
  - Latest Release: `v2026.11.10` (`2026-11-25T05:42:47Z`)
- **License**: `MIT` (`LICENSE` and `THIRD_PARTY_NOTICES.md` verified at repo root; GitHub API `spdx_id=MIT`).
- **Platform & Dependencies**: TypeScript / Node.js Gateway runtime.

---

## Verified Mechanisms, Files & Behavior

1. **Loop Detection (`docs/tools/loop-detection.md`)**:
   - Compares `(tool_name, canonical_args)` with the immediately preceding call (key-order-insensitive, **does not compare results**).
   - 3rd consecutive identical call injects a system warning; 20th blocks and terminates the turn with `tool_repeat_limit`.
   - Configurable via `tools.loopDetection.enabled` with per-agent overrides and `repeatable: true` / `repeatable: { actions: [...] }` exemptions.
   - Missing/unavailable tool calls are counted by tool name only.

2. **Subagent Queuing & Budgets (`docs/tools/subagents/operations.md`)**:
   - Spawning session owns an in-process queue (`maxConcurrent=8`, `maxChildrenPerAgent=5`; Swarm collector lane `maxConcurrent=32`, `maxChildrenPerGroup=50`, `maxTotalPerGroup=200`).
   - **Architectural divergence from Grokbot-clon**: nested orchestrator children consume from the intermediate orchestrator's budget rather than a single root-shared budget.

3. **Liveness, Crash Recovery & Cascading Cancellation (`docs/tools/subagents/operations.md`)**:
   - Explicitly avoids trusting `endedAt=None` as proof of liveness across process restarts; clears stale counts after a stale-run window (`2h` or `timeout + grace`) and expires suspended completion deliveries after 7 days with a visible notice.
   - Graceful shutdown records root requesters, cleanly aborts running children (distinguishing shutdown from user cancellation), and repairs pending `Gateway stopped` completions on startup.
   - Cascading abort (`stop`, `chat.abort`, `sessions.abort`, `/acp cancel`) cancels queued/yielded child rows and retires pending inputs.

---

## Engineering Verdict for Grokbot-clon

- **Adopt Conceptually**:
  - Cascading cancellation from root run down to active/queued child runs, retiring pending inputs and keeping terminal `cancelled` immutable against late results (`A09`).
  - Distinguishing process crash/shutdown (`recovering`) from explicit user cancellation (`cancelled`).
  - Never treating missing completion timestamps (`endedAt=None`) as live across coordinator restarts without checking active lease ownership and expiry (`A14`).
  - Counting unavailable/missing tool calls by tool name to prevent repeat stalls.
- **Discard**:
  - Per-spawner isolated subagent budgets (Grokbot-clon enforces a root-shared hierarchical budget with `max_depth=1`).
  - High default concurrency (`8`/`32`).
  - Args-only previous-call loop detection without result hashing (insufficient for `A07` alternating cycles).
