# Comparative Analysis: Sandboxes, Secret Boundaries & Event Streams

Covers **NanoClaw**, **IronClaw**, and **OpenHands** (inspected `2026-11-25T09:13–09:17Z`). All three are classified as **Patrón estudiado** (clean-room behavioral reference only; zero code vendored).

---

## 1. NanoClaw (`nanocoai/nanoclaw`)
- **Repository**: `https://github.com/nanocoai/nanoclaw`
- **Verified Commit / Release**: `main` SHA `9774cb596a32039d9464d78174ec5ed9531a9898` (`2026-11-24T18:08:09Z`) · Release `v2026.11.0` (`2026-11-20T18:45:10Z`)
- **License**: `MIT` (`LICENSE` verified at root).
- **Platform & Dependencies**: TypeScript/Node.js, SQLite, Docker or macOS Apple Containers, Claude Code / Agent SDK.
- **Core Mechanism**:
  - Single Node.js host process + SQLite mailbox (`v2.db`) polling loop dispatching ephemeral unprivileged (`uid 1000`) containers per group (`data/sessions/{group}/`).
  - Mounts host project root read-only and enforces an external non-agent-modifiable `~/.config/nanoclaw/mount-allowlist.json` blocking `.ssh`, `.aws`, `.env`, `.docker`, and private key paths.
- **Verdict for Grokbot-clon**:
  - **Adopt conceptually**: External non-agent-modifiable allowlists and read-only policy mounts for M7 software factory (`src/factory/`) and tool boundaries so an autonomous improvement agent cannot edit acceptance policies or read host credentials.
  - **Discard**: Chat-channel mailbox model and Claude-SDK coupling.

---

## 2. IronClaw (`nearai/ironclaw`)
- **Repository**: `https://github.com/nearai/ironclaw`
- **Verified Commit / Release**: `main` SHA `b0b999d96781516ee05e6ba961d6f3ead900da96` (`2026-09-10T18:55:51Z`) · Release `ironclaw-v1.4.1` (`2026-09-29T20:40:32Z`)
- **License**: Dual `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE` at root; GitHub API reports `Apache-2.0`).
- **Platform & Dependencies**: Rust, WASM runtime, Docker, PostgreSQL / libSQL.
- **Core Mechanism**:
  - Rust single-binary Agent OS running untrusted tools/extensions in WASM sandboxes + Docker with proxy-mediated egress.
  - Capability-based permissions and an encrypted secret store where **secrets never enter LLM context** and are injected solely at the egress/tool boundary.
- **Verdict for Grokbot-clon**:
  - **Adopt conceptually**: Core security invariant — credentials, cookies, and API keys never enter LLM prompts or persisted `ActionReceipt`s (enforced fail-closed in `src/contracts/redaction.py` + `ActionReceipt` validator in M1, and adapter-boundary secret injection in M3).
  - **Discard**: Rust/WASM rewrite overhead for MVP (Python 3.12 monolith chosen in `ADR-0001`).

---

## 3. OpenHands (`OpenHands/OpenHands`)
- **Repository**: `https://github.com/OpenHands/OpenHands`
- **Verified Commit / Release**: `main` SHA `adf71d626b81a0db00902e0d3edf2b00d2cf917c` (`2026-11-25T04:20:32Z`) · Release `v1.45.0` (`2026-11-24T09:13:54Z`)
- **License**: `MIT` (`LICENSE` verified at root).
- **Platform & Dependencies**: Python + TypeScript/React + Docker/Kubernetes, Keycloak, PostgreSQL, Redis, LiteLLM.
- **Core Mechanism**:
  - Decoupled Agent Canvas (React/TS) + `openhands.sdk` Agent Server + isolated Docker/K8s Runtime API.
  - Typed **append-only event stream** (`Action`, `Observation`, `Thought`) driving reproducible execution history and reactive observers.
- **Verdict for Grokbot-clon**:
  - **Adopt conceptually**: Typed append-only event stream (`ActionReceipt` -> `Observation` -> audit log) for both the core engine (`src/engine/`, `src/storage/`) and the M7 autonomous software factory (`src/factory/`).
  - **Discard**: Heavy multi-service enterprise stack (Keycloak, Postgres, Redis, K8s) for single-host MVP.
