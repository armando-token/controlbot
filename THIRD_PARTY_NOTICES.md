# Third-Party Notices & Provenance Inventory

**Generated**: `2026-11-25` (M1 Lock Baseline)
**Source Lockfile**: `uv.lock` (Python `3.12.15`, `requires-python = ">=3.12,<3.13"`)

---

## 1. Clean-Room Provenance Policy (Megaplan §3.2 & §3.3)

Grokbot-clon distinguishes strictly between **studied behavioral patterns** and **incorporated dependencies**:
1. **Patrón estudiado (Zero Code Vendored)**:
   - The 13 surveyed external projects documented in `docs/research/` (`Rakazo`, `Hermes Agent`, `OpenClaw`, `OpenMausBot`, `NanoClaw`, `IronClaw`, `OpenHands`, `Playwright MCP`, `agent-browser`, `Browser Use`, `Cua`, `Munim Computer Use`, `CUA-JEV`) are **reference designs only**.
   - **Zero** source files, tests, or fragments from those repositories are copied or vendored into `src/`.
   - **Explicit Quarantine**: `milind-soni/OpenMausBot/enterprise/` (source-available `OpenMausBot Enterprise License` requiring paid/partner keys) is quarantined and completely unused.
2. **Dependencia incorporada**:
   - All runtime and development Python packages incorporated into Grokbot-clon are pinned in `pyproject.toml` and `uv.lock` below, using permissive OSI-approved licenses (`MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`, `PSF-2.0`, `MPL-2.0`).

---

## 2. Direct Python Dependencies (Exact `uv.lock` Versions)

| Package | Locked Version (`uv.lock`) | Scope | Verified License | Upstream Repository / URL |
|---|---|---|---|---|
| `pydantic` | `2.14.4` | Runtime | `MIT` | `https://github.com/pydantic/pydantic` |
| `fastapi` | `0.165.0` | Runtime | `MIT` | `https://github.com/fastapi/fastapi` |
| `uvicorn` | `0.54.0` | Runtime | `BSD-3-Clause` | `https://github.com/Kludex/uvicorn` |
| `httpx` | `0.28.1` | Runtime | `BSD-3-Clause` | `https://github.com/encode/httpx` |
| `jinja2` | `3.1.6` | Runtime | `BSD-3-Clause` | `https://github.com/pallets/jinja` |
| `playwright` | `1.64.0` | Runtime | `Apache-2.0` | `https://github.com/microsoft/playwright-python` |
| `pytest` | `8.4.2` | Dev | `MIT` | `https://github.com/pytest-dev/pytest` |
| `pytest-asyncio` | `0.26.0` | Dev | `Apache-2.0` | `https://github.com/pytest-dev/pytest-asyncio` |
| `ruff` | `0.17.6` | Dev | `MIT` | `https://github.com/astral-sh/ruff` |
| `mypy` | `1.20.2` | Dev | `MIT` | `https://github.com/python/mypy` |

---

## 3. Transitive Python Dependencies in `uv.lock`

Verified from `uv.lock` and installed `.venv` `.dist-info` metadata:

| Package | Locked Version | Verified License (from `.dist-info` / PyPI) |
|---|---|---|
| `annotated-doc` | `0.0.7` | `MIT` |
| `annotated-types` | `0.8.0` | `MIT` |
| `anyio` | `4.16.0` | `MIT` |
| `certifi` | `2026.11.20` | `MPL-2.0` |
| `click` | `8.5.1` | `BSD-3-Clause` |
| `colorama` | `0.4.6` | `BSD-3-Clause` *(conditional Windows marker in `uv.lock`; not installed on macOS/Linux)* |
| `greenlet` | `3.5.6` | `MIT AND PSF-2.0` |
| `h11` | `0.16.0` | `MIT` |
| `httpcore` | `1.0.9` | `BSD-3-Clause` |
| `httptools` | `0.9.0` | `MIT` |
| `idna` | `3.20` | `BSD-3-Clause` |
| `iniconfig` | `2.3.1` | `MIT` |
| `librt` | `0.17.0` | `MIT` |
| `markupsafe` | `3.0.4` | `BSD-3-Clause` |
| `mypy-extensions` | `1.2.0` | `MIT` |
| `opentelemetry-api` | `1.45.2` | `Apache-2.0` |
| `packaging` | `26.4` | `Apache-2.0 OR BSD-2-Clause` |
| `pathspec` | `1.1.1` | `MPL-2.0` |
| `pluggy` | `1.7.0` | `MIT` |
| `pydantic-core` | `2.50.5` | `MIT` |
| `pyee` | `14.0.0` | `MIT` |
| `pygments` | `2.21.0` | `BSD-2-Clause` |
| `python-dotenv` | `1.2.4` | `BSD-3-Clause` |
| `pyyaml` | `6.0.4` | `MIT` |
| `starlette` | `1.10.0` | `BSD-3-Clause` |
| `typing-extensions` | `4.16.0` | `PSF-2.0` |
| `typing-inspection` | `0.4.5` | `MIT` |
| `uvloop` | `0.23.0` | `MIT` |
| `watchfiles` | `1.3.0` | `MIT` |
| `websockets` | `17.4` | `BSD-3-Clause` |

---

## 4. Playwright Browser Binaries & FFmpeg Notices

Playwright (`playwright==1.64.0`, `Apache-2.0`) manages external browser binaries in the OS Playwright cache (`~/Library/Caches/ms-playwright` on macOS, `~/.cache/ms-playwright` on Linux):

- **Chromium (`chromium-1248`, `chromium_headless_shell-1248`)**:
  - Governed primarily by `BSD-3-Clause` (`https://chromium.googlesource.com/chromium/src/+/refs/heads/main/LICENSE`) along with embedded third-party component notices (`MIT`, `ISC`, etc.).
  - Any offline/air-gapped bundle (`M8`) that redistributes Chromium binaries must preserve Chromium's `LICENSE` and third-party notice files.
- **FFmpeg (`ffmpeg-1013`, optionally installed by Playwright for video capture)**:
  - Governed primarily by `LGPL-2.1+` (with some optional configurations under GPL; see `https://ffmpeg.org/legal.html`).
  - Grokbot-clon does not link against FFmpeg in Python source; offline Linux packaging (`M8`) must explicitly document whether Playwright's optional FFmpeg binary is excluded or redistributed with its corresponding `LGPL-2.1+` notices.
