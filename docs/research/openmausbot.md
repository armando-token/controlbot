# Candidate Analysis: OpenMausBot

- **Classification**: **Patrón estudiado** (core architectural concepts only; **`enterprise/` strictly quarantined**)
- **Owner & Repository**: `milind-soni` (Milind Soni / Supamaus Software Private Limited) · `https://github.com/milind-soni/OpenMausBot`
- **Verified Provenance (inspected `2026-11-25T09:13–09:17Z`)**:
  - `main` HEAD: `96ff844559a1bb07b4d1e555e464db6bfb490f64` (`2026-11-25T07:48:59Z`)
  - Latest Release: `v0.1.180` (`2026-11-24T12:05:11Z`)
- **License & Quarantine Warning**:
  - **MIXED / CARVE-OUT**: Core repository is `Apache-2.0` (`LICENSE`, `NOTICE`), **EXCEPT `enterprise/` is source-available under `OpenMausBot Enterprise License` (`LICENSING.md`, `enterprise/LICENSE`)**, which requires a paid or partner key for production or hosted use.
  - Trademark notice restricts `OpenMausBot` / `MausBot`.
  - Per Megaplan §3.2 & §3.3, `enterprise/` is quarantined and zero code or fragments from OpenMausBot are used in Grokbot-clon.
- **Platform & Dependencies**: TypeScript, Node.js (>=24), pnpm, Electron, Docker + Caddy; requires external authenticated agent CLIs (`claude`, `codex`, `grok`) for real inference.

---

## Verified Mechanisms, Files & Behavior

1. **Loopback Harness & External CLI Wrapping**:
   - Runs a local loopback harness server (`127.0.0.1`) that spawns external agent CLI binaries (`claude`, `codex`, `grok` via `ENGINES` in Docker) and normalizes heterogeneous XML/JSON CLI streams into a unified event stream.
   - Stores local state under `~/.openmausbot`.
   - Includes a permission broker that pauses high-risk tool calls for human allow/deny decisions.

2. **Local Deployment & Process Hygiene (`deploy/local/README.md`)**:
   - Uses Docker Compose + Caddy over Unix sockets (`edge` volume).
   - Enforces `OMB_BIND_ADDRESS=127.0.0.1` and `OMB_TRUSTED_PROXY_CIDRS` to prevent spoofed HTTPS host headers.
   - Runs an `init` process inside containers to reap orphaned child/zombie subprocesses.

---

## Engineering Verdict for Grokbot-clon

- **Adopt Conceptually**:
  - Default loopback-only binding (`127.0.0.1`) for local Web API/UI (`src/web/`) plus trusted-proxy header validation.
  - Subprocess zombie reaping (`init` / explicit process-group cleanup) when managing Playwright/lab subprocesses.
  - Human permission/takeover pause gate before high-risk or ambiguous actions.
  - Normalized backend event/decision interface across heterogeneous model backends (`ModelClient` -> `EmulatedModelClient` & `LocalHttpModelClient`).
- **Discard**:
  - Wrapping external commercial CLIs (`claude`, `codex`, `grok`) — incompatible with Megaplan's internet-blocked local LLM LAN requirement.
  - Node.js/Electron UI stack.
  - Anything inside `enterprise/` (non-OSS source-available carve-out).
