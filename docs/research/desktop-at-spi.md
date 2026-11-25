# Comparative Analysis: Linux Desktop, AT-SPI & Guarded Action Loops (`F11`, `F12`)

Covers **Cua**, **Munim Computer Use**, and **CUA-JEV** (inspected `2026-11-25T09:13–09:17Z`).

---

## 1. Cua (`trycua/cua`)
- **Repository**: `https://github.com/trycua/cua`
- **Verified Commit / Release**: `main` SHA `848e2a561a5f8b01286d855afb58bc1ac19a150c` (`2026-11-25T09:02:16Z`) · Release `cua-spaces-v0.41.12` (`2026-11-25T03:16:47Z`)
- **License**: `MIT` (`LICENSE.md` verified at root: `Copyright (c) 2025 Cua AI, Inc.`; hosted/commercial services have separate terms).
- **Core Mechanism**: Cross-OS sandboxes and `Cua Driver` (Rust core + Python SDKs) supporting macOS, Windows, and Linux desktops.
- **Verdict for Grokbot-clon**:
  - **Reference only for M4/M5 Linux desktop probe (`F12`)**: Too heavy for the M1–M3 web-only MVP; keep behind Grokbot-clon's desktop adapter interface (`src/adapters/`).

---

## 2. Munim Computer Use (`munimtechnologies/munim-computer-use`)
- **Repository**: `https://github.com/munimtechnologies/munim-computer-use`
- **Verified Commit / Release**: `main` SHA `b816c1e5d3f40e4e47cef96f9cad52e6ae10e0a9` (`2026-11-20T07:30:25Z`) · Release `v0.14.2` (`2026-11-20T07:36:44Z`)
- **License**: `Apache-2.0` (`LICENSE` verified at root).
- **Platform & Build Dependencies**: Rust MCP stdio server (`windows-linux/`) driving Linux via **AT-SPI + X11 (XTEST)** (`libdrm-devel`, `mesa-libgbm-devel`, `mesa-libEGL-devel`, `wayland-devel`, `libxcb-devel`).
- **Verified Linux Mechanism & Geometry Constraint (`README.md` L486)**:
  - *"element actions work everywhere; coordinate clicks need an X11 or XWayland client, since native Wayland apps do not expose absolute geometry."*
  - On Linux, pointer actions move the real cursor (`via cursor`), whereas AT-SPI element actions (`press`, `set value`) execute structurally without moving the cursor.
- **Verdict for Grokbot-clon**:
  - **Adopt architectural insight for `F12` (`Patrón estudiado`)**: Prioritize AT-SPI element actions first, explicitly separate X11/XWayland vs native Wayland capability reporting (Megaplan §4.5 & §5 M5), enforce app allowlists outside the model (`policy.json` pattern), and report `PENDING_N3_LINUX_ENV` on macOS. Do not bundle the Rust binary in M1–M3.

---

## 3. CUA-JEV (`ZJU-REAL/CUA-JEV`)
- **Repository**: `https://github.com/ZJU-REAL/CUA-JEV`
- **Verified Commit / Release**: `main` SHA `eb7ce36e541d92b44c4cf0573334294fd40569d5` (`2026-11-24T09:20:29Z`) · GitHub Releases: `NONE` (`404` on `/releases/latest`).
- **License & Provenance Note**: GitHub API returns `license=NOASSERTION` due to formatting/whitespace, **but direct inspection of `LICENSE` and `pyproject.toml` (`license = { text = "Apache-2.0" }`) confirms `Apache-2.0` (`Copyright 2026 CUA-JEV contributors`)**.
- **Core Mechanism & Symbols**:
  - Python >=3.11 framework (`src/cua_jev/models.py` `ActionCandidate`, `runtime.py` `AgentRuntime`, `guard.py` `ActionGuard`, `registry.py` `ExecutorRegistry`).
  - Implements **Observe -> Select (`intent x channel` candidate ID) -> Guard (`ActionGuard` checks freshness, identity, scope, permissions) -> Execute -> Independent Verifier + JSONL trace**.
  - **Platform Constraint**: `pyproject.toml` & `README.md` L74 show it is **Windows-first** (`windows = ["pywin32", "pywinauto", "pyautogui", "openpyxl"]`, `browser = ["playwright>=1.48"]`); no Linux AT-SPI/X11/Wayland backend exists in `pyproject.toml`.
- **Verdict for Grokbot-clon**:
  - **Adopt conceptually (`Patrón estudiado`)**: `Observe -> Legal ActionCandidate -> ActionGuard (freshness/identity/scope/permissions) -> Execute -> Independent Verifier` loop and typed candidate selection — directly informing Grokbot-clon's §4.5 industrial adapter loop and semantic disambiguation (`A02`).
  - **Discard**: Windows-only (`pywin32`, `pywinauto`) dependencies and external `Jev` API dependency.
