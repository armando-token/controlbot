# Comparative Analysis: Browser Automation (`F10`)

Covers **Playwright**, **Playwright MCP**, **agent-browser**, and **Browser Use** (inspected `2026-11-25T09:13–09:17Z`).

---

## 1. Playwright & Playwright MCP (`microsoft/playwright`, `microsoft/playwright-mcp`)
- **Repositories & Verified Commits / Releases**:
  - `microsoft/playwright`: `https://github.com/microsoft/playwright` · `main` SHA `b0e0b7b555e637cc8c0ce94dd98c3be153861333` (`2026-11-25T00:44:14Z`) · Release `v1.65.1` (`2026-11-13T21:46:58Z`) · PyPI `playwright==1.65.2` (Grokbot-clon pins `playwright==1.64.0` to match cached host `chromium-1248`)
  - `microsoft/playwright-mcp`: `https://github.com/microsoft/playwright-mcp` · `main` SHA `2337aff0213d28db41d3e3daf48cee19b3d0bd82` (`2026-11-18T18:49:18Z`) · Release `v0.0.86` (`2026-11-18T18:50:38Z`)
- **License**: `Apache-2.0` (`LICENSE` in both repos; PyPI `playwright` `license_expression='Apache-2.0'`). Separate notices apply to downloaded browser binaries: Chromium (`BSD-3-Clause` + third-party notices) and optional FFmpeg (`LGPL-2.1+`).
- **Platform & Dependencies**: Python (`playwright`) + OS browser binaries (macOS & Linux Chromium/WebKit/Firefox).
- **Core Mechanism**:
  - Isolated `BrowserContext`s (or `launch_persistent_context` keyed per `(user_id, profile_id, app_id)`).
  - Semantic/role/label/ARIA locators (`get_by_role`, `get_by_label`, `get_by_text`), deterministic auto-waiting, and trace capture.
  - Playwright MCP exposes structured accessibility-tree snapshots (text/ARIA refs instead of raw screenshots).
- **Verdict for Grokbot-clon**:
  - **Adopt as primary MVP browser dependency (`Dependencia incorporada`)**: `playwright==1.64.0` Python package + isolated `BrowserContext`/persistent user-data-dir per `(user_id, profile_id, app_id)` + semantic/DOM locators first. Keep Playwright MCP as an optional interoperable adapter pattern (`F08`), not a mandatory runtime process.

---

## 2. agent-browser (`vercel-labs/agent-browser`)
- **Repository**: `https://github.com/vercel-labs/agent-browser`
- **Verified Commit / Release**: `main` SHA `f0a98351ec920bd826b22c98dacf8414f04b9832` (`2026-11-25T03:25:51Z`) · Release `v0.44.0` (`2026-11-23T22:44:34Z`)
- **License**: `Apache-2.0` (`LICENSE` verified at root).
- **Core Mechanism**: Native Rust CLI driving CDP directly with token-efficient accessibility snapshots and `@e1`-style element refs.
- **Verified Risk (documented in Rakazo `docs/computer-runtime.md` L67)**:
  - Has no built-in domain allowlist over CDP.
  - Ref matching can click a replacement element with the same role/name (even on another page) if not re-validated against a fresh snapshot immediately prior to acting.
- **Verdict for Grokbot-clon**:
  - **Adopt conceptually**: Compact accessibility snapshots with element refs + mandatory fresh-snapshot re-validation before acting.
  - **Discard as dependency**: Adding a separate Rust CLI over CDP in MVP is unnecessary when Playwright Python provides stronger frame, origin, and persistent-context isolation natively.

---

## 3. Browser Use (`browser-use/browser-use`)
- **Repository**: `https://github.com/browser-use/browser-use`
- **Verified Commit / Release**: `main` SHA `94784c1f7ecb6b0a5f565b7f9fba59e395b7e048` (`2026-11-24T22:48:11Z`) · Release `1.0.8` (`2026-11-22T03:30:41Z`)
- **License**: `MIT` (`LICENSE` verified at root; Browser Use Cloud carries separate commercial ToS).
- **Core Mechanism**: Python LLM-driven DOM/vision browser agent loop layered on Playwright/CDP.
- **Verdict for Grokbot-clon**:
  - **Discard as dependency**: Couples the LLM planner directly into the browser loop, undermining Grokbot-clon's deterministic state machine, `ExecutionPlan` pre-validation, shared budget accounting, and independent value/unit/quality verification.
