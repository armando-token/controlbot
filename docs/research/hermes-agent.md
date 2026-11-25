# Candidate Analysis: Hermes Agent

- **Classification**: **Patrón estudiado** (behavioral reference only; zero code vendored)
- **Owner & Repository**: `NousResearch` · `https://github.com/NousResearch/hermes-agent`
- **Verified Provenance (inspected `2026-11-25T09:13–09:17Z`)**:
  - `main` HEAD: `2fcdbfea1847a1119901835d5970fdca2b3d8ea8` (`2026-11-25T07:11:03Z`) — matches Megaplan line 352 pinned commit
  - Latest Release: `v0.23.4` (`2026-11-24T08:17:06Z`)
- **License**: `MIT` (`LICENSE` verified at repo root; GitHub API `spdx_id=MIT`).
- **Platform & Dependencies**: Python + Linux Xfce gateway (for Bot Screen) + Desktop client.

---

## Verified Mechanisms, Files & Symbols

1. **Side-Effect-Free Guardrail & Loop Detection (`agent/tool_guardrails.py` at `2fcdbfea1847a1119901835d5970fdca2b3d8ea8`)**:
   - Symbols: `ToolCallGuardrailController`, `ToolCallGuardrailConfig`, `LoopCapConfig`, `ToolCallSignature`, `ToolGuardrailDecision`, `IdenticalCallObservation`, `before_call()`, `after_call()`, `observe_call()`, `_detect_identical_cycle()`.
   - Detects repeated identical `(tool, canonical_args, result_hash)` calls — **even when the tool returns success** — with `STALL_GUARD_IDENTICAL_CALL_THRESHOLD = 3`.
   - Detects alternating multi-call cycles via `_detect_identical_cycle()` across periods `2.._STALL_GUARD_MAX_CYCLE_PERIOD=4` over `period * 3` steps.
   - Distinguishes `IDEMPOTENT_TOOL_NAMES` (`read_file`, `browser_snapshot`, etc.) and explicit repeatable pollers (`STALL_GUARD_REPEATABLE_TOOLS = {"process_manage"}`, suffixes `_get_result`, `_poll`).
   - Default turn caps: `_DEFAULT_MAX_WEB_SEARCHES_PER_TURN = 50`, `_DEFAULT_MAX_SUBAGENTS_PER_TURN = 50`.

2. **Subagent Delegation & Bot Screen (`tools/delegate_tool.py`, `website/docs/developer-guide/tools-runtime.md`, `website/docs/user-guide/features/bot-screen`)**:
   - `delegate_task` spawns isolated child `AIAgent` instances capped by `delegation.oneshot_max_children`.
   - Bot Screen runs a headless Linux Xfce gateway streamed to Hermes Desktop with human takeover for login/2FA.

3. **Critical Gap Identified**:
   - `ToolCallGuardrailController.reset_for_turn()` stores observations in-memory per turn only. It does **not** persist loop or budget state across coordinator restarts (`A14`) and does **not** pool a shared token/tool/wall-clock budget across root + child runs.

---

## Engineering Verdict for Grokbot-clon

- **Adopt Conceptually**:
  - Pure, typed guardrail controller interface returning explicit decisions (`allow`, `warn`, `synthetic_result`, `halt`).
  - Canonical JSON argument + result-hash signatures to catch **successful** no-progress repeats (`A06`) and alternating cycles of period `2..4` (`A07`), while allowing registered pollers with explicit progress/timeout rules.
  - Persistent extension in Grokbot-clon: store step observation signatures and shared root+child budget counters in SQLite WAL so restarts never reset counters (`A14`).
- **Discard**:
  - In-memory per-turn-only state (`reset_for_turn()`).
  - Permissive `50`-subagent/search defaults (Grokbot-clon caps at `2` active children, `depth=1`, `16` tool calls, `8` model calls per `BudgetConfig`).
  - Xfce streaming desktop UI.
