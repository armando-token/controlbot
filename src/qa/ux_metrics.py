"""UX quality telemetry, layout checks, error actionability, and PNG screenshot checkpoints."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from playwright.async_api import Page
from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.qa.isolation import (
    _redact_encoded_auth,
    _sanitize_record,
    assert_safe_mutation_path,
    contains_encoded_auth,
    contains_unredacted_url_secret,
)
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
    redact_string_strict,
)

PNG_MAGIC: bytes = b"\x89PNG\r\n\x1a\n"

_M3_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![A-Za-z0-9])sk-(?:proj|live|test|ant|svcacct)?-?[A-Za-z0-9_-]{12,}"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{20,}"),
)

_ACTIONABLE_PHRASE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:retry|reconnect|reload|try\s+again)\b"),
    re.compile(
        r"(?i)\bswitch\s+(?:to|engine|backend|mode|model|profile|account|bot|tab)\b"
    ),
    re.compile(
        r"(?i)\bplease\s+(?:check|verify|select|enable|authorize|approve|deny|"
        r"provide|configure|install|start|launch|open|contact)\b"
    ),
    re.compile(
        r"(?i)\b(?:check|verify)\s+(?:your|the|that|whether|settings|network|"
        r"connection|logs|permissions?|config|credentials?|status)\b"
    ),
    re.compile(
        r"(?i)\b(?:install|configure|enable|authorize|approve|provide|select)\s+"
        r"(?:the|a|an|your|[a-z0-9_-]{2,})\b"
    ),
    re.compile(r"(?i)\bcontact\s+(?:support|admin|administrator|operator)\b"),
    re.compile(
        r"(?i)\b(?:start|launch)\s+(?:the\s+)?(?:server|browser|session|service|"
        r"daemon|vnc|docker|app|terminal)\b"
    ),
    re.compile(
        r"(?i)\bopen\s+(?:settings|the\s+\w+|a\s+new|computer|modal|panel|dialog|"
        r"preferences|vault|page)\b"
    ),
    re.compile(r"(?i)\b(?:request|grant|allow|deny)\s+(?:permission|access|approval)\b"),
)

_RAW_DUMP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"net::ERR_[A-Z_]+"),
    re.compile(r"\[Errno\s+\d+\]"),
    re.compile(
        r"\b(?:OSError|RuntimeError|ValueError|TypeError|KeyError|AttributeError|"
        r"ImportError|ConnectionError|TimeoutError|FileNotFoundError|PermissionError|"
        r"sqlite3\.\w*Error)\s*:"
    ),
    re.compile(r'"available_sources"\s*:\s*\['),
    re.compile(r'"missing_sources"\s*:\s*\['),
)

_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def _scrub_m3_tokens(text: str) -> str:
    sanitized = _sanitize_record(text)
    scrubbed = redact_string_strict(
        _redact_encoded_auth(sanitized if isinstance(sanitized, str) else str(sanitized))
    )
    for pattern in _M3_TOKEN_PATTERNS:
        scrubbed = pattern.sub(REDACTED_PLACEHOLDER, scrubbed)
    return _redact_encoded_auth(scrubbed)


def _has_m3_token(text: str) -> bool:
    return (
        any(pattern.search(text) for pattern in _M3_TOKEN_PATTERNS)
        or contains_encoded_auth(text)
        or contains_unredacted_url_secret(text)
    )


def redact_payload_m3(value: Any) -> Any:
    """Apply `redact_payload_strict`, URL/encoded-auth scrubbing, and M3 API token scrubbing."""
    strict_redacted = redact_payload_strict(_sanitize_record(value))

    def _walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            return {_walk(k): _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, tuple):
            return tuple(_walk(item) for item in node)
        if isinstance(node, set):
            return {_walk(item) for item in node}
        if isinstance(node, frozenset):
            return frozenset(_walk(item) for item in node)
        if isinstance(node, str):
            return _scrub_m3_tokens(node)
        return node

    return _walk(strict_redacted)


def contains_unredacted_secret_m3(value: Any) -> bool:
    """Return True if strict redaction OR M3 token patterns detect an unredacted secret."""
    if contains_unredacted_secret_strict(value):
        return True
    if isinstance(value, Mapping):
        return any(
            contains_unredacted_secret_m3(k) or contains_unredacted_secret_m3(v)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_unredacted_secret_m3(item) for item in value)
    if isinstance(value, str):
        return _has_m3_token(value)
    return _has_m3_token(str(value)) if value is not None else False


class ScreenshotCheckpoint(FrozenModel):
    """Metadata and integrity hash for a captured PNG UI checkpoint."""

    checkpoint_id: NonEmptyStr
    case_id: NonEmptyStr
    label: NonEmptyStr
    path: NonEmptyStr
    captured_at: UtcDatetime = Field(default_factory=utc_now)
    is_error_state: bool = False
    byte_size: int = Field(ge=0)
    sha256: NonEmptyStr


class UxTimingResult(FrozenModel):
    """UX interaction timing and cancel affordance measurement."""

    actions_to_reach: int = Field(ge=0)
    ttfp_ms: float | None = Field(default=None, ge=0.0)
    completion_ms: float = Field(ge=0.0)
    cancel_available: bool = False


class UxFlowMetrics(FrozenModel):
    """UX quality telemetry for a single QA flow or control probe."""

    case_id: NonEmptyStr
    run_id: NonEmptyStr
    actions_to_reach: int = Field(ge=0)
    error_actionable: bool | None = None
    ttfp_ms: float | None = Field(default=None, ge=0.0)
    completion_ms: float = Field(ge=0.0)
    focus_predictable: bool = True
    cancel_available: bool = False
    local_remote_indicator_visible: bool = False
    local_remote_location: str = ""
    response_persisted_on_reload: bool | None = None
    result_clarity_notes: str = ""
    composer_layout_intact: bool = True
    screenshots: list[ScreenshotCheckpoint] = Field(default_factory=list)
    measured_at: UtcDatetime = Field(default_factory=utc_now)


class UxMetricReport(FrozenModel):
    """Aggregated UX telemetry report persisted as `ux_metrics.json`."""

    campaign_id: NonEmptyStr
    generated_at: UtcDatetime = Field(default_factory=utc_now)
    flows: list[UxFlowMetrics] = Field(default_factory=list)
    screenshots: list[ScreenshotCheckpoint] = Field(default_factory=list)


def _slugify(raw: str) -> str:
    lowered = raw.strip().lower().replace(" ", "_")
    cleaned = _SLUG_RE.sub("_", lowered).strip("_")
    return cleaned[:48] or "checkpoint"


def validate_png_file(path: Path) -> tuple[int, str]:
    """Verify a PNG file has valid magic bytes and non-empty content, returning (size, sha256)."""
    if not path.is_file():
        raise FileNotFoundError(f"Screenshot file does not exist: {path}")
    raw = path.read_bytes()
    if len(raw) <= len(PNG_MAGIC) or not raw.startswith(PNG_MAGIC):
        raise ValueError(f"Invalid PNG screenshot at {path}: size={len(raw)}")
    digest = hashlib.sha256(raw).hexdigest()
    return len(raw), digest


async def measure_ux_action[T](
    action: Callable[[], Awaitable[T]],
    *,
    actions_to_reach: int = 1,
    ttfp_probe: Callable[[], Awaitable[bool]] | None = None,
    cancel_available: bool = False,
    poll_interval_s: float = 0.02,
) -> tuple[T, UxTimingResult]:
    """Measure TTFP and completion latency of an async UX action without busy-looping."""
    started = time.monotonic()
    ttfp_ms: float | None = None
    stop_polling = asyncio.Event()
    effective_interval = max(0.005, float(poll_interval_s))

    async def _poll_progress() -> None:
        nonlocal ttfp_ms
        if ttfp_probe is None:
            return
        while not stop_polling.is_set():
            with contextlib.suppress(Exception):
                if await ttfp_probe():
                    ttfp_ms = (time.monotonic() - started) * 1000.0
                    return
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop_polling.wait(), timeout=effective_interval)

    poller = asyncio.create_task(_poll_progress()) if ttfp_probe is not None else None
    try:
        result = await action()
    finally:
        stop_polling.set()
        if poller is not None:
            with contextlib.suppress(Exception):
                await poller

    completion_ms = (time.monotonic() - started) * 1000.0
    if ttfp_probe is None:
        ttfp_ms = completion_ms

    return result, UxTimingResult(
        actions_to_reach=actions_to_reach,
        ttfp_ms=ttfp_ms,
        completion_ms=completion_ms,
        cancel_available=cancel_available,
    )


async def capture_screenshot_checkpoint(
    page: Page,
    *,
    output_dir: Path,
    case_id: str,
    label: str,
    is_error_state: bool = False,
    repo_root: Path | None = None,
) -> ScreenshotCheckpoint:
    """Capture a full-page PNG checkpoint under `<output_dir>/screenshots/` and verify magic."""
    safe_out = assert_safe_mutation_path(output_dir, repo_root=repo_root)
    shots_dir = safe_out / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)

    case_slug = _slugify(case_id)
    label_slug = _slugify(label)
    suffix = "_error" if is_error_state else ""
    base_name = f"{case_slug}_{label_slug}{suffix}"
    shot_path = shots_dir / f"{base_name}.png"
    counter = 1
    while shot_path.exists():
        counter += 1
        shot_path = shots_dir / f"{base_name}_{counter}.png"

    await page.screenshot(path=str(shot_path), full_page=True)
    byte_size, sha256 = validate_png_file(shot_path)
    checkpoint_id = f"shot-{shot_path.stem}-{sha256[:8]}"
    return ScreenshotCheckpoint(
        checkpoint_id=checkpoint_id,
        case_id=case_id,
        label=label,
        path=str(shot_path),
        is_error_state=is_error_state,
        byte_size=byte_size,
        sha256=sha256,
    )


async def check_local_remote_indicator(page: Page) -> tuple[bool, str]:
    """Check whether local-vs-remote execution indicator is visible at top level vs buried."""
    top_level_probe = await page.evaluate(
        """() => {
            const isVisible = (el) => {
                const st = window.getComputedStyle(el);
                if (st.display === 'none' || st.visibility === 'hidden') return false;
                const r = el.getBoundingClientRect();
                return r.width > 0 || r.height > 0;
            };
            const badgeSelectors = [
                '[data-testid*="runtime"]',
                '[data-testid*="origin"]',
                '[data-testid*="backend"]',
                '[data-runtime-mode]',
                '[data-llm-origin]',
                '[aria-label*="runtime" i]',
                '[aria-label*="origin" i]',
                '[aria-label*="backend mode" i]',
            ].join(', ');
            const badges = Array.from(document.querySelectorAll(badgeSelectors));
            for (const b of badges) {
                if (b.closest('[role="dialog"]')) continue;
                if (!isVisible(b)) continue;
                const txt = (b.innerText || b.getAttribute('aria-label') || '').trim();
                if (txt) {
                    return { found: true, keyword: txt };
                }
            }

            const explicitPatterns = [
                /\\bbackend_mode\\b/i,
                /\\bllm_origin\\b/i,
                /\\bruntime_mode\\b/i,
                /\\blocal_http\\b/i,
                /\\blive_runtime\\b/i,
                /\\bagy_real\\b/i,
                /\\bcontrolbot_runtime\\b/i,
                /\\blocal\\s+(?:runtime|model|backend|mode)\\b/i,
                /\\bremote\\s+cloud\\b/i,
                /\\bcloud\\s+(?:runtime|backend)\\b/i,
                /\\bemulated\\s+(?:mode|runtime|backend|llm)\\b/i,
                /\\b(?:runtime|origin|backend|mode)\\s*:\\s*(?:local|remote|cloud|emulated|live_runtime|local_http|agy_real)\\b/i,
            ];
            const containers = Array.from(document.querySelectorAll('header, aside'));
            for (const container of containers) {
                const candidates = Array.from(
                    container.querySelectorAll('[role="status"], span, div, small, code, p')
                );
                for (const el of candidates) {
                    if (!isVisible(el)) continue;
                    // Skip roster thread/bot buttons in <aside> unless explicitly marked as status.
                    if (
                        container.tagName.toLowerCase() === 'aside'
                        && el.closest('button, a')
                        && el.getAttribute('role') !== 'status'
                    ) {
                        continue;
                    }
                    const txt = (el.innerText || '').trim();
                    if (!txt) continue;
                    for (const pat of explicitPatterns) {
                        const match = txt.match(pat);
                        if (match) {
                            return { found: true, keyword: match[0] };
                        }
                    }
                }
            }
            return { found: false, keyword: '' };
        }"""
    )
    if isinstance(top_level_probe, dict) and top_level_probe.get("found"):
        kw = str(top_level_probe.get("keyword", "")).strip()
        return True, f"top_level_workspace ({kw})"

    # Check if buried inside Settings -> System & Tasks without leaving modal open.
    settings_btn = page.locator('aside button[aria-label="Settings"]')
    if await settings_btn.count() > 0 and await settings_btn.first.is_visible():
        try:
            await settings_btn.first.click(timeout=3000)
            dialog = page.locator('[role="dialog"][aria-modal="true"]')
            await dialog.wait_for(state="visible", timeout=5000)
            sys_tab = dialog.get_by_role("button", name="System & Tasks")
            if await sys_tab.count() > 0:
                await sys_tab.first.click(timeout=3000)
                with contextlib.suppress(Exception):
                    await dialog.get_by_text("backend_mode", exact=True).wait_for(
                        state="visible", timeout=2500
                    )
                text = (await dialog.inner_text()).lower()
                if "backend_mode" in text or "llm_origin" in text or "runtime_mode" in text:
                    return False, "buried_in_settings: Settings -> System & Tasks (3 clicks)"
        except Exception:
            pass
        finally:
            try:
                await page.keyboard.press("Escape")
                await page.locator('[role="dialog"][aria-modal="true"]').wait_for(
                    state="hidden", timeout=3000
                )
            except Exception:
                pass

    return False, "not_visible_top_level"


async def check_composer_single_row(page: Page) -> tuple[bool, str]:
    """Check whether Send/Stop buttons stay aligned on a single toolbar row without overlap."""
    result = await page.evaluate(
        """() => {
            const isVisible = (el) => {
                if (!el) return false;
                const st = window.getComputedStyle(el);
                if (st.display === 'none' || st.visibility === 'hidden') return false;
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            };
            const sendBtn = document.querySelector('button[aria-label="Send message"]');
            const stopBtn = document.querySelector('button[aria-label="Stop current generation"]');
            const actionBtn = isVisible(stopBtn) ? stopBtn : (isVisible(sendBtn) ? sendBtn : null);
            if (!actionBtn) {
                return {
                    present: false,
                    intact: true,
                    reason: 'composer_action_button_not_rendered',
                };
            }

            const textarea = document.querySelector('textarea[aria-label="Message composer"]');
            const namedPeers = [
                document.querySelector('button[aria-label="Attach files"]'),
                document.querySelector('button[aria-label="Start voice dictation"]'),
                document.querySelector('button[aria-label="Stop voice dictation"]'),
                document.querySelector('select[aria-label="Turn model override"]'),
                document.querySelector('select[aria-label="Turn thinking level override"]'),
                document.querySelector(
                    'select[aria-label="Include browser context for this message"]'
                ),
            ];
            const peerSet = new Set();
            const toolbarPeers = [];
            const addPeer = (el) => {
                if (!el || el === actionBtn || el === textarea || peerSet.has(el)) return;
                if (!isVisible(el)) return;
                peerSet.add(el);
                toolbarPeers.push(el);
            };
            for (const p of namedPeers) addPeer(p);
            const bar = actionBtn.parentElement;
            if (bar) {
                const barControls = Array.from(
                    bar.querySelectorAll('button, select, input:not([type="hidden"])')
                );
                for (const ctrl of barControls) addPeer(ctrl);
            }

            const aRect = actionBtn.getBoundingClientRect();
            const overlapCheckList = isVisible(textarea)
                ? [textarea, ...toolbarPeers]
                : toolbarPeers;
            for (const peer of overlapCheckList) {
                const pRect = peer.getBoundingClientRect();
                const overlapX = aRect.left < pRect.right - 1 && aRect.right > pRect.left + 1;
                const overlapY = aRect.top < pRect.bottom - 1 && aRect.bottom > pRect.top + 1;
                if (overlapX && overlapY) {
                    const peerLabel = (
                        peer.getAttribute('aria-label')
                        || peer.getAttribute('title')
                        || peer.innerText
                        || peer.tagName.toLowerCase()
                    ).trim();
                    return {
                        present: true,
                        intact: false,
                        reason: `Action button overlaps sibling control (${peerLabel})`,
                    };
                }
            }

            for (const peer of toolbarPeers) {
                const pRect = peer.getBoundingClientRect();
                if (aRect.top >= pRect.bottom - 2 || pRect.top >= aRect.bottom - 2) {
                    const peerLabel = (
                        peer.getAttribute('aria-label')
                        || peer.getAttribute('title')
                        || peer.innerText
                        || peer.tagName.toLowerCase()
                    ).trim();
                    const sendTop = Math.round(aRect.top);
                    const peerBot = Math.round(pRect.bottom);
                    return {
                        present: true,
                        intact: false,
                        reason:
                            `Send button wrapped onto second row `
                            + `(top=${sendTop} vs ${peerLabel} bottom=${peerBot})`,
                    };
                }
                if (pRect.left < aRect.left && aRect.left < pRect.right - 2) {
                    const sendLeft = Math.round(aRect.left);
                    const peerRight = Math.round(pRect.right);
                    return {
                        present: true,
                        intact: false,
                        reason:
                            `Send button misaligned horizontally `
                            + `(left=${sendLeft} vs peerRight=${peerRight})`,
                    };
                }
            }
            return { present: true, intact: true, reason: 'single_row_aligned' };
        }"""
    )
    if not isinstance(result, dict):
        return True, "unable_to_evaluate"
    intact = bool(result.get("intact", True))
    reason = str(result.get("reason", "unknown"))
    return intact, reason


def evaluate_error_actionability(visible_text: str) -> tuple[bool, str]:
    """Assess whether visible error text is human-readable, secret-free, and actionable."""
    cleaned = visible_text.strip()
    if not cleaned:
        return False, "Empty error text provides no explanation or recovery action."
    if contains_unredacted_secret_m3(cleaned):
        return False, "Error text exposes unredacted secret material."
    for pattern in _RAW_DUMP_PATTERNS:
        if pattern.search(cleaned):
            return False, f"Error text exposes raw diagnostic/stack dump ({pattern.pattern})."
    has_guidance = any(pattern.search(cleaned) for pattern in _ACTIONABLE_PHRASE_PATTERNS)
    if not has_guidance:
        return False, "Error message lacks a clear recovery or next-step action for the operator."
    return True, "Actionable, secret-free error message."


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def save_ux_metrics(
    report_or_metrics: UxMetricReport | Sequence[UxFlowMetrics],
    output_path: Path,
    *,
    campaign_id: str = "ux-metrics",
    repo_root: Path | None = None,
) -> Path:
    """Redact, validate against secret leaks, and atomically write UX telemetry JSON."""
    safe_path = assert_safe_mutation_path(output_path, repo_root=repo_root)
    if isinstance(report_or_metrics, UxMetricReport):
        report = report_or_metrics
    else:
        flows = list(report_or_metrics)
        shots: list[ScreenshotCheckpoint] = []
        seen_ids: set[str] = set()
        for flow in flows:
            for shot in flow.screenshots:
                if shot.checkpoint_id not in seen_ids:
                    seen_ids.add(shot.checkpoint_id)
                    shots.append(shot)
        report = UxMetricReport(
            campaign_id=campaign_id,
            flows=flows,
            screenshots=shots,
        )

    raw_payload = json.loads(report.model_dump_json())
    redacted_payload = redact_payload_m3(raw_payload)
    if contains_unredacted_secret_m3(redacted_payload):
        raise ValueError("Refusing to write UX metrics containing unredacted secrets.")
    _atomic_write_json(safe_path, redacted_payload)
    return safe_path


__all__ = [
    "PNG_MAGIC",
    "ScreenshotCheckpoint",
    "UxFlowMetrics",
    "UxMetricReport",
    "UxTimingResult",
    "capture_screenshot_checkpoint",
    "check_composer_single_row",
    "check_local_remote_indicator",
    "contains_unredacted_secret_m3",
    "evaluate_error_actionability",
    "measure_ux_action",
    "redact_payload_m3",
    "save_ux_metrics",
    "validate_png_file",
]
