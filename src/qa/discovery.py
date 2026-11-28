"""Automated static + live Playwright UI control discovery and state-transition matrix."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import fcntl
import json
import re
import subprocess
from collections.abc import Coroutine, Iterator, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from playwright.async_api import Locator, Page, Request
from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, utc_now
from src.qa.isolation import (
    IsolatedLabServer,
    StrictPlaywrightSession,
    assert_not_live_target,
    assert_safe_mutation_path,
)
from src.qa.models import ControlInventoryItem, CoverageReport, CoverageStatus
from src.qa.ux_metrics import (
    ScreenshotCheckpoint,
    capture_screenshot_checkpoint,
    check_composer_single_row,
    check_local_remote_indicator,
    contains_unredacted_secret_m3,
    redact_payload_m3,
)

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]

_INTERACTIVE_TAGS: frozenset[str] = frozenset({"button", "input", "textarea", "select", "a"})
_INTERACTIVE_ROLES: frozenset[str] = frozenset(
    {"button", "tab", "menuitem", "switch", "checkbox", "radio", "dialog", "combobox"}
)
_DESTRUCTIVE_KEYWORDS: tuple[str, ...] = (
    "delete",
    "remove",
    "force handback",
    "reset",
    "logout",
    "clear",
    "discard",
)
_CLICK_MUTATE_KEYWORDS: tuple[str, ...] = (
    "create bot",
    "create group chat",
    "send message",
    "save changes",
    "save securely",
    "fill directly",
    "add secret",
    "add skill",
    "add routine",
)

_ATTR_STR_RE = re.compile(
    r"""([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{\s*['"`]([^'"`]*)['"`]\s*\})"""
)
_ATTR_BOOL_RE = re.compile(r"""\b(disabled|autoFocus|readOnly)\b(?:\s*=\s*\{([^}]*)\})?""")
_HTML_FOR_RE = re.compile(r"""<label[^>]*\bhtmlFor\s*=\s*["']([^"']+)["'][^>]*>([^<]*)""")
_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


class StaticControlSpec(FrozenModel):
    """Static UI control metadata extracted from React TSX/JSX sources."""

    control_id: NonEmptyStr
    module: NonEmptyStr
    route: NonEmptyStr
    role: NonEmptyStr
    accessible_name: str
    selector: NonEmptyStr
    source_file: NonEmptyStr
    line_number: int = Field(ge=1)
    precondition: str = ""
    requires_overlay: str | None = None
    repeatable: bool = True
    test_case_id: str | None = None
    a11y_gaps: list[str] = Field(default_factory=list)


class DiscoveryProbeResult(FrozenModel):
    """Combined static + live Playwright discovery result and UX/a11y findings."""

    coverage: CoverageReport
    coverage_path: str | None = None
    screenshots: list[ScreenshotCheckpoint] = Field(default_factory=list)
    silent_noop_controls: list[str] = Field(default_factory=list)
    focus_defects: list[str] = Field(default_factory=list)
    missing_label_controls: list[str] = Field(default_factory=list)
    local_remote_indicator_visible: bool = False
    local_remote_location: str = ""
    composer_layout_intact: bool = True
    console_errors: list[str] = Field(default_factory=list)
    page_errors: list[str] = Field(default_factory=list)
    http_errors: list[str] = Field(default_factory=list)
    external_requests: list[str] = Field(default_factory=list)


def _slugify(value: str) -> str:
    cleaned = _SLUG_RE.sub("_", value.strip().lower().replace(" ", "_")).strip("_")
    return cleaned[:40] or "ctrl"


def _infer_module_and_route(rel_path: str) -> tuple[str, str, str | None, str | None]:
    norm = rel_path.replace("\\", "/").lstrip("/")
    name = Path(norm).name

    module = "shell"
    if norm.startswith("features/roster/") or "/features/roster/" in norm:
        module = "roster"
    elif norm.startswith("features/chat/") or "/features/chat/" in norm:
        module = "chat"
    elif norm.startswith("features/computer/") or "/features/computer/" in norm:
        module = "computer"
    elif norm.startswith("features/artifacts/") or "/features/artifacts/" in norm:
        module = "artifacts"
    elif norm.startswith("features/settings/") or "/features/settings/" in norm:
        module = "settings"
    elif norm.startswith("features/memory/") or "/features/memory/" in norm:
        module = "memory"
    elif norm.startswith("features/routines/") or "/features/routines/" in norm:
        module = "routines"
    elif norm.startswith("features/hitl/") or "/features/hitl/" in norm:
        module = "hitl"

    overlay_map: dict[str, tuple[str, str | None, str | None]] = {
        "CreateBotModal.tsx": ("/app#modal:create-bot", "CreateBotModal", "CB-04"),
        "CreateChannelModal.tsx": ("/app#modal:create-channel", "CreateChannelModal", "CB-04"),
        "HiddenBotsDrawer.tsx": ("/app#modal:hidden-bots", "HiddenBotsDrawer", "CB-04"),
        "SettingsDialog.tsx": ("/app#modal:settings", "SettingsDialog", "CB-08"),
        "ConnectAppsModal.tsx": ("/app#modal:connect-apps", "ConnectAppsModal", "CB-08"),
        "ShortcutsDialog.tsx": ("/app#modal:shortcuts", "ShortcutsDialog", "CB-00"),
        "CommandPalette.tsx": ("/app#modal:command-palette", "CommandPalette", "CB-04"),
        "MemoryModal.tsx": ("/app#modal:memory", "MemoryModal", "CB-08"),
        "FullScreenTakeoverModal.tsx": (
            "/app#modal:fullscreen-computer",
            "FullScreenTakeoverModal",
            "CB-06",
        ),
        "RoutineModals.tsx": ("/app#modal:routines", "RoutineModals", "CB-08"),
        "ComputerTab.tsx": ("/app#inspector:computer", "InspectorPanel:Computer", "CB-06"),
        "LiveVncCanvas.tsx": ("/app#inspector:computer", "InspectorPanel:Computer", "CB-06"),
        "TerminalTab.tsx": ("/app#inspector:computer", "InspectorPanel:Computer", "CB-06"),
        "WorkspaceFilesTab.tsx": ("/app#inspector:computer", "InspectorPanel:Computer", "CB-06"),
        "LibraryTab.tsx": ("/app#inspector:library", "InspectorPanel:Library", "CB-05"),
        "BotDetailsTab.tsx": ("/app#inspector:details", "InspectorPanel:Details", "CB-08"),
        "InspectorPanel.tsx": ("/app#inspector", "InspectorPanel", "CB-00"),
        "ApprovalCard.tsx": ("/app#hitl", "HITLCard", "CB-07"),
        "EditableDraftCard.tsx": ("/app#hitl", "HITLCard", "CB-07"),
        "SecureFormCard.tsx": ("/app#hitl", "HITLCard", "CB-07"),
        "InteractivePageViewer.tsx": ("/app#page", "SplitPageWorkspace", "CB-05"),
        "SplitPageWorkspace.tsx": ("/app#page", "SplitPageWorkspace", "CB-05"),
        "MediaLightbox.tsx": ("/app#modal:media-lightbox", "MediaLightbox", "CB-05"),
        "ComposerBox.tsx": ("/app#chat", None, "CB-01"),
        "ChatHeader.tsx": ("/app#chat", None, "CB-00"),
        "TranscriptViewport.tsx": ("/app#chat", None, "CB-01"),
        "VerdictCard.tsx": ("/app#chat", None, "CB-11"),
        "BotRosterSidebar.tsx": ("/app", None, "CB-04"),
        "AppShell.tsx": ("/app", None, "CB-00"),
        "App.tsx": ("/app", None, "CB-00"),
    }
    route, overlay, case_id = overlay_map.get(name, ("/app", None, "CB-00"))
    return module, route, overlay, case_id


_CLOSING_TAG_RE = re.compile(r"</\s*([A-Za-z_][A-Za-z0-9_.]*)?\s*>")
_RESIDUAL_CODE_RE = re.compile(r"(?:\)\s*;\s*\}|\)\s*;|\breturn\s+|=>|<path\b)")


def _skip_brace_expression(source: str, start: int, limit: int) -> int:
    """Advance past a balanced `{...}` JS/JSX expression respecting quotes and comments."""
    depth = 1
    quote: str | None = None
    escaped = False
    pos = start + 1
    while pos < limit and depth > 0:
        cur = source[pos]
        if quote is not None:
            if escaped:
                escaped = False
            elif cur == "\\":
                escaped = True
            elif cur == quote:
                quote = None
            pos += 1
            continue
        if cur == "/" and pos + 1 < limit:
            nxt = source[pos + 1]
            if nxt == "/":
                nl = source.find("\n", pos + 2, limit)
                pos = (nl + 1) if nl != -1 else limit
                continue
            if nxt == "*":
                end_c = source.find("*/", pos + 2, limit)
                pos = (end_c + 2) if end_c != -1 else limit
                continue
        if cur in ('"', "'", "`"):
            quote = cur
            pos += 1
            continue
        if cur == "{":
            depth += 1
        elif cur == "}":
            depth -= 1
        pos += 1
    return pos


def _scan_jsx_opening_tag(source: str, start: int, limit: int) -> tuple[str, int, bool] | None:
    """Parse a JSX opening tag at `<` (`start`), returning `(tag_name, end_idx, self_closing)`."""
    if start + 1 >= limit or not (source[start + 1].isalpha() or source[start + 1] == "_"):
        return None
    if start > 0 and (source[start - 1].isalnum() or source[start - 1] in "_$)"):
        return None

    j = start + 1
    while j < limit and (source[j].isalnum() or source[j] in "_."):
        j += 1
    tag_name = source[start + 1 : j]
    if j < limit and not (source[j].isspace() or source[j] in "/>"):
        return None

    brace_depth = 0
    quote: str | None = None
    escaped = False
    k = j
    while k < limit:
        cur = source[k]
        if quote is not None:
            if escaped:
                escaped = False
            elif cur == "\\":
                escaped = True
            elif cur == quote:
                quote = None
            k += 1
            continue
        if brace_depth > 0 and cur == "/" and k + 1 < limit:
            nxt = source[k + 1]
            if nxt == "/":
                nl = source.find("\n", k + 2, limit)
                k = (nl + 1) if nl != -1 else limit
                continue
            if nxt == "*":
                end_c = source.find("*/", k + 2, limit)
                k = (end_c + 2) if end_c != -1 else limit
                continue
        if cur in ('"', "'", "`"):
            quote = cur
            k += 1
            continue
        if cur == "{":
            brace_depth += 1
            k += 1
            continue
        if cur == "}":
            if brace_depth > 0:
                brace_depth -= 1
            k += 1
            continue
        if brace_depth == 0:
            if cur in ";?&|<()":
                return None
            if cur == "/" and k + 1 < limit and source[k + 1] == ">":
                return tag_name, k + 2, True
            if cur == ">":
                return tag_name, k + 1, False
        k += 1
    return None


def _iter_jsx_opening_tags(source: str) -> list[tuple[str, str, int, int, bool]]:
    """Scan JSX opening tags respecting nested `{...}` expressions, JS comments, and quotes."""
    results: list[tuple[str, str, int, int, bool]] = []
    n = len(source)
    i = 0
    while i < n:
        if source[i] != "<":
            i += 1
            continue
        parsed = _scan_jsx_opening_tag(source, i, n)
        if parsed is None:
            i += 1
            continue
        tag_name, tag_end, self_closing = parsed
        line_num = source.count("\n", 0, i) + 1
        tag_text = source[i:tag_end]
        results.append((tag_name, tag_text, tag_end, line_num, self_closing))
        i = tag_end
    return results


def _skip_svg_block(source: str, svg_body_start: int, limit: int) -> int:
    """Advance past an `<svg>...</svg>` block including nested `<svg>` or `{...}` expressions."""
    depth = 1
    pos = svg_body_start
    while pos < limit and depth > 0:
        ch = source[pos]
        if ch == "{":
            pos = _skip_brace_expression(source, pos, limit)
            continue
        if ch == "<":
            m_close = _CLOSING_TAG_RE.match(source, pos)
            if m_close:
                if (m_close.group(1) or "").lower() == "svg":
                    depth -= 1
                pos = m_close.end()
                continue
            parsed = _scan_jsx_opening_tag(source, pos, limit)
            if parsed is not None:
                c_name, c_end, c_self = parsed
                if c_name.lower() == "svg" and not c_self:
                    depth += 1
                pos = c_end
                continue
        pos += 1
    return pos


def _extract_inner_text(source: str, body_start: int, tag_name: str = "") -> str:
    """Extract visible inner text strictly bounded by the element's matching closing tag."""
    limit = min(len(source), body_start + 16000)
    pos = body_start
    same_tag_depth = 1
    parts: list[str] = []

    while pos < limit:
        ch = source[pos]
        if ch == "{":
            pos = _skip_brace_expression(source, pos, limit)
            parts.append(" ")
            continue
        if ch == "<":
            m_close = _CLOSING_TAG_RE.match(source, pos)
            if m_close:
                close_name = m_close.group(1) or ""
                pos = m_close.end()
                parts.append(" ")
                if tag_name and close_name == tag_name:
                    same_tag_depth -= 1
                    if same_tag_depth == 0:
                        break
                elif not tag_name:
                    break
                continue
            if pos + 1 < limit and source[pos + 1] == ">":
                pos += 2
                parts.append(" ")
                continue
            parsed = _scan_jsx_opening_tag(source, pos, limit)
            if parsed is not None:
                c_name, c_end, c_self = parsed
                if c_name.lower() == "svg":
                    pos = c_end if c_self else _skip_svg_block(source, c_end, limit)
                    parts.append(" ")
                    continue
                if tag_name and c_name == tag_name and not c_self:
                    same_tag_depth += 1
                pos = c_end
                parts.append(" ")
                continue
        parts.append(ch)
        pos += 1

    raw_text = " ".join("".join(parts).split()).strip()
    if _RESIDUAL_CODE_RE.search(raw_text):
        raw_text = _RESIDUAL_CODE_RE.split(raw_text, maxsplit=1)[0].strip()
    if len(raw_text) > 80:
        raw_text = raw_text[:80].rstrip()
    return raw_text


def discover_static_controls(frontend_src_dir: Path) -> list[StaticControlSpec]:
    """Extract UI control specs and static a11y gaps across `frontend/src/` TSX/JSX files."""
    if not frontend_src_dir.is_dir():
        return []

    files = sorted(
        {
            *frontend_src_dir.rglob("*.tsx"),
            *frontend_src_dir.rglob("*.jsx"),
        },
        key=lambda p: str(p.relative_to(frontend_src_dir)),
    )

    specs: list[StaticControlSpec] = []
    seen_ids: set[str] = set()

    for file_path in files:
        rel = str(file_path.relative_to(frontend_src_dir))
        source = file_path.read_text(encoding="utf-8", errors="replace")
        module, route, overlay, case_id = _infer_module_and_route(rel)
        label_fors = {
            match.group(1).strip(): match.group(2).strip()
            for match in _HTML_FOR_RE.finditer(source)
            if match.group(1).strip()
        }
        has_tab_trap = bool(re.search(r"""\.key\s*===\s*['"]Tab['"]""", source))
        has_escape_handler = bool(re.search(r"""\.key\s*===\s*['"]Escape['"]""", source))

        for tag_name, tag_text, body_start, line_num, self_closing in _iter_jsx_opening_tags(
            source
        ):
            tag_low = tag_name.lower()
            attrs: dict[str, str] = {}
            for m in _ATTR_STR_RE.finditer(tag_text):
                val = m.group(2) if m.group(2) is not None else (m.group(3) or m.group(4) or "")
                attrs[m.group(1)] = val.strip()

            role = attrs.get("role", "").lower()
            test_id = attrs.get("data-testid", "")
            aria_modal = attrs.get("aria-modal", "").lower()
            elem_id = attrs.get("id", "")
            class_name = attrs.get("className", "")

            is_interactive = (
                tag_low in _INTERACTIVE_TAGS
                or role in _INTERACTIVE_ROLES
                or aria_modal == "true"
                or bool(test_id)
            )
            if not is_interactive:
                continue
            if tag_low == "input" and attrs.get("type", "").lower() == "file" and (
                "hidden" in class_name.split() or "sr-only" in class_name.split()
            ):
                continue

            aria_label = attrs.get("aria-label", "")
            title = attrs.get("title", "")
            placeholder = attrs.get("placeholder", "")
            html_label = label_fors.get(elem_id, "")
            inner_text = "" if self_closing else _extract_inner_text(source, body_start, tag_name)

            accessible_name = (
                aria_label or title or placeholder or html_label or inner_text or test_id or elem_id
            ).strip()
            if len(accessible_name) > 120:
                accessible_name = accessible_name[:120].rstrip()

            if role:
                effective_role = role
            elif tag_low in {"input", "textarea"}:
                effective_role = "textbox"
            elif tag_low == "select":
                effective_role = "combobox"
            elif tag_low == "a":
                effective_role = "link"
            else:
                effective_role = tag_low

            if test_id:
                selector = f'[data-testid="{test_id}"]'
            elif elem_id:
                selector = f"#{elem_id}"
            elif aria_label:
                selector = f'{tag_low}[aria-label="{aria_label}"]'
            elif role == "dialog" and aria_modal == "true":
                selector = '[role="dialog"][aria-modal="true"]'
            elif placeholder:
                selector = f'{tag_low}[placeholder="{placeholder}"]'
            elif title:
                selector = f'{tag_low}[title="{title}"]'
            elif inner_text and tag_low in {"button", "a"} and len(inner_text) <= 48:
                escaped_txt = inner_text.replace('"', '\\"')
                selector = f'{tag_low}:has-text("{escaped_txt}")'
            else:
                selector = f"{tag_low}[data-qa-line='{Path(rel).stem}:{line_num}']"

            a11y_gaps: list[str] = []
            if not (aria_label or html_label or placeholder or title) and (
                tag_low in {"input", "textarea", "select"} or not inner_text
            ):
                a11y_gaps.append("missing_accessible_label")
            if (
                role == "dialog"
                and aria_modal == "true"
                and Path(rel).name != "Modal.tsx"
                and not has_tab_trap
            ):
                a11y_gaps.append("missing_modal_focus_trap")
            if (
                attrs.get("aria-haspopup")
                and 'role="menu"' not in source
                and not has_escape_handler
            ):
                a11y_gaps.append("missing_menu_role_or_escape")

            lowered_name = accessible_name.lower()
            repeatable = not any(
                tok in lowered_name for tok in (*_DESTRUCTIVE_KEYWORDS, *_CLICK_MUTATE_KEYWORDS)
            )

            base_slug = _slugify(accessible_name or elem_id or effective_role)
            control_id = f"static:{module}:{Path(rel).stem.lower()}:{base_slug}:{line_num}"
            if control_id in seen_ids:
                control_id = f"{control_id}_{len(seen_ids)}"
            seen_ids.add(control_id)

            precondition = f"Requires {overlay} open" if overlay else "Workspace /app loaded"
            specs.append(
                StaticControlSpec(
                    control_id=control_id,
                    module=module,
                    route=route,
                    role=effective_role,
                    accessible_name=accessible_name,
                    selector=selector,
                    source_file=rel,
                    line_number=line_num,
                    precondition=precondition,
                    requires_overlay=overlay,
                    repeatable=repeatable,
                    test_case_id=case_id,
                    a11y_gaps=a11y_gaps,
                )
            )

    return specs


async def probe_modal_focus_cycle(
    page: Page,
    trigger_selector: str,
    *,
    close_key: str = "Escape",
) -> tuple[bool, str | None]:
    """Open modal from trigger, verify dialog focus trap (Tab/Shift+Tab), close & check restore."""
    trigger = page.locator(trigger_selector).first
    if await trigger.count() == 0:
        return False, f"Modal trigger {trigger_selector!r} not found in DOM"
    if not await trigger.is_visible():
        return False, f"Modal trigger {trigger_selector!r} is not visible"

    await trigger.focus()
    await trigger.evaluate("(el) => { window.__qaModalTrigger = el; }")
    await trigger.click(timeout=5000)

    dialog = page.locator('[role="dialog"][aria-modal="true"] >> visible=true').first
    try:
        await dialog.wait_for(state="visible", timeout=5000)
    except Exception:
        return (
            False,
            f"Dialog [role='dialog'][aria-modal='true'] did not open for {trigger_selector!r}",
        )

    # Allow React useEffect focus placement to run.
    await page.wait_for_timeout(80)
    _inspect_dialog_js = """() => {
        const dialogs = Array.from(document.querySelectorAll('[role="dialog"][aria-modal="true"]'));
        const visible = dialogs.find((d) => {
            const st = window.getComputedStyle(d);
            const r = d.getBoundingClientRect();
            return st.display !== 'none' && st.visibility !== 'hidden' && r.width > 0;
        });
        if (!visible) {
            return { inside: false, focusableCount: 0 };
        }
        const focusableSelector = [
            'a[href]',
            'button:not([disabled])',
            'input:not([disabled]):not([type="hidden"])',
            'select:not([disabled])',
            'textarea:not([disabled])',
            'summary',
            '[tabindex]:not([tabindex="-1"])',
            '[contenteditable="true"]',
        ].join(', ');
        const focusables = Array.from(visible.querySelectorAll(focusableSelector)).filter((el) => {
            if (el.getAttribute('aria-hidden') === 'true') return false;
            const st = window.getComputedStyle(el);
            if (st.display === 'none' || st.visibility === 'hidden') return false;
            const r = el.getBoundingClientRect();
            return r.width > 0 || r.height > 0;
        });
        return {
            inside: visible.contains(document.activeElement),
            focusableCount: focusables.length,
        };
    }"""
    dialog_state = await page.evaluate(_inspect_dialog_js)
    inside = bool(isinstance(dialog_state, dict) and dialog_state.get("inside"))
    if not inside:
        await page.keyboard.press(close_key)
        return False, f"Focus did not enter modal dialog for {trigger_selector!r}"

    focusable_count = (
        int(dialog_state.get("focusableCount", 0)) if isinstance(dialog_state, dict) else 0
    )
    tab_steps = max(4, focusable_count + 2)
    shift_tab_steps = max(3, focusable_count + 1)

    for step in range(tab_steps):
        await page.keyboard.press("Tab")
        step_state = await page.evaluate(_inspect_dialog_js)
        trapped = bool(isinstance(step_state, dict) and step_state.get("inside"))
        if not trapped:
            await page.keyboard.press(close_key)
            return False, f"Tab #{step + 1} escaped modal focus trap for {trigger_selector!r}"

    for step in range(shift_tab_steps):
        await page.keyboard.press("Shift+Tab")
        step_state = await page.evaluate(_inspect_dialog_js)
        trapped = bool(isinstance(step_state, dict) and step_state.get("inside"))
        if not trapped:
            await page.keyboard.press(close_key)
            return (
                False,
                f"Shift+Tab #{step + 1} escaped modal focus trap for {trigger_selector!r}",
            )

    await page.keyboard.press(close_key)
    try:
        await dialog.wait_for(state="hidden", timeout=5000)
    except Exception:
        return False, f"Modal dialog did not close on {close_key!r} for {trigger_selector!r}"

    await page.wait_for_timeout(80)
    restore_info = await page.evaluate(
        """() => {
            const active = document.activeElement;
            if (!active || active === document.body || active === document.documentElement) {
                return { ok: false, reason: 'body_fallback' };
            }
            if (window.__qaModalTrigger && active === window.__qaModalTrigger) {
                return { ok: true, reason: 'restored_to_trigger' };
            }
            const label = active.getAttribute('aria-label') || active.tagName || 'unknown';
            return { ok: false, reason: 'wrong_target:' + label };
        }"""
    )
    if not isinstance(restore_info, dict) or not restore_info.get("ok"):
        reason = restore_info.get("reason") if isinstance(restore_info, dict) else "unknown"
        if reason == "body_fallback":
            return (
                False,
                f"Focus fell back to BODY after closing modal triggered by {trigger_selector!r}",
            )
        return False, f"Focus failed to restore to trigger {trigger_selector!r} ({reason})"
    return True, None


async def _snapshot_control_state(locator: Locator) -> dict[str, Any]:
    raw = await locator.evaluate(
        """(el) => {
            const active = document.activeElement;
            const dialogs = document.querySelectorAll('[role="dialog"][aria-modal="true"]').length;
            const menus = document.querySelectorAll('[role="menu"], [role="listbox"]').length;
            const root = document.querySelector('#root') || document.body;
            const rootTextLen = (root ? root.innerText : '').length;
            const rootHtml = root ? root.innerHTML : '';
            const rootHtmlLen = rootHtml.length;
            const elOuterHtml = el.outerHTML || '';
            const nonSelfHtml = elOuterHtml
                ? rootHtml.replace(elOuterHtml, '__QA_SELF__')
                : rootHtml;
            const alertText = Array.from(
                document.querySelectorAll(
                    '[role="alert"], [role="status"], [aria-live="polite"], [aria-live="assertive"]'
                )
            )
                .map((n) => (n.innerText || '').trim())
                .filter(Boolean)
                .join(' | ');
            const interactiveCount = document.querySelectorAll(
                'button, input, textarea, select, a, [role="dialog"], [role="menu"]'
            ).length;
            return {
                exists: true,
                tag: el.tagName.toLowerCase(),
                disabled: Boolean(el.disabled) || el.getAttribute('aria-disabled') === 'true',
                ariaPressed: el.getAttribute('aria-pressed'),
                ariaExpanded: el.getAttribute('aria-expanded'),
                ariaSelected: el.getAttribute('aria-selected'),
                className: String(el.className || ''),
                title: (el.getAttribute('title') || '').trim(),
                ariaDescribedBy: el.getAttribute('aria-describedby') || '',
                disabledReason: (el.getAttribute('data-disabled-reason') || '').trim(),
                alertText,
                dialogs,
                menus,
                rootTextLen,
                rootHtmlLen,
                nonSelfHtmlLen: nonSelfHtml.length,
                nonSelfHtmlSample: nonSelfHtml.slice(0, 4096),
                interactiveCount,
                activeIsSelf: active === el,
                activeTag: active ? active.tagName.toLowerCase() : '',
                activeId: active ? (active.id || active.getAttribute('aria-label') || '') : '',
                elHtmlSample: rootHtml.slice(0, 4096),
            };
        }"""
    )
    return raw if isinstance(raw, dict) else {"exists": False}


async def probe_control_state_transition(
    page: Page,
    selector: str,
    *,
    allow_mutation: bool = False,
) -> tuple[CoverageStatus, str, str, str | None]:
    """Probe a live control once for disabled explanations, state changes, or silent no-ops."""
    locator = page.locator(selector).first
    if await locator.count() == 0:
        return (
            "pending",
            "not_rendered",
            "not_rendered",
            f"Control {selector} is not rendered in the active view",
        )
    try:
        visible = await locator.is_visible()
    except Exception:
        visible = False
    if not visible:
        return (
            "pending",
            "hidden",
            "hidden",
            f"Control {selector} is present in DOM but currently hidden",
        )

    info = await locator.evaluate(
        """(el) => {
            const descId = el.getAttribute('aria-describedby');
            const descEl = descId ? document.getElementById(descId) : null;
            const descText = descEl ? (descEl.innerText || '').trim() : '';
            const title = (el.getAttribute('title') || '').trim();
            const disabledReason = (el.getAttribute('data-disabled-reason') || '').trim();
            const label = (
                el.getAttribute('aria-label') ||
                el.innerText ||
                el.getAttribute('placeholder') ||
                el.id ||
                ''
            ).trim();
            return {
                tag: el.tagName.toLowerCase(),
                type: (el.getAttribute('type') || '').toLowerCase(),
                role: (el.getAttribute('role') || '').toLowerCase(),
                id: (el.id || '').trim(),
                testId: (el.getAttribute('data-testid') || '').trim(),
                disabled: Boolean(el.disabled) || el.getAttribute('aria-disabled') === 'true',
                explanation: disabledReason || descText || title,
                label: label,
            };
        }"""
    )

    tag = str(info.get("tag", ""))
    is_disabled = bool(info.get("disabled", False))
    explanation = str(info.get("explanation", "")).strip()
    label = str(info.get("label", "")).strip()

    if is_disabled:
        if explanation:
            return (
                "blocked",
                "disabled",
                "disabled (explained)",
                f"Disabled under current precondition ({explanation})",
            )
        return (
            "blocked",
            "disabled",
            "disabled (unexplained)",
            "Disabled control lacks user-facing explanation (no title/aria-describedby)",
        )

    lowered_label = label.lower()
    norm_ident = re.sub(
        r"[-_]+",
        " ",
        f"{lowered_label} {str(info.get('id', '')).lower()} {str(info.get('testId', '')).lower()}",
    )
    if not allow_mutation:
        if any(tok in norm_ident for tok in _DESTRUCTIVE_KEYWORDS):
            return (
                "out_of_scope",
                "enabled",
                "skipped_destructive",
                "Destructive control skipped when allow_mutation=False",
            )
        if any(tok in norm_ident for tok in _CLICK_MUTATE_KEYWORDS):
            return (
                "out_of_scope",
                "enabled",
                "skipped_mutating",
                "Mutation disallowed (allow_mutation=False)",
            )

    if tag in {"input", "textarea", "select"}:
        try:
            await locator.focus(timeout=2000)
            focused = await locator.evaluate("(el) => document.activeElement === el")
            if focused:
                return ("covered", "enabled", "focusable_input_ready", None)
        except Exception as exc:
            return ("blocked", "enabled", "focus_failed", f"Input focus failed: {exc}")

    before = await _snapshot_control_state(locator)
    url_before = page.url
    requests_fired: list[str] = []

    def _on_request(req: Request) -> None:
        requests_fired.append(f"{req.method} {req.url}")

    page.on("request", _on_request)
    try:
        await locator.evaluate(
            """(el) => {
                window.__qaLastProbedEl = el;
            }"""
        )
        await locator.click(timeout=3000)
        await page.wait_for_timeout(150)
    except Exception as exc:
        return ("blocked", "enabled", "click_error", f"Click failed on {selector}: {exc}")
    finally:
        page.remove_listener("request", _on_request)

    after_url = page.url
    after = await page.evaluate(
        """() => {
            const el = window.__qaLastProbedEl;
            const active = document.activeElement;
            const dialogs = document.querySelectorAll('[role="dialog"][aria-modal="true"]').length;
            const menus = document.querySelectorAll('[role="menu"], [role="listbox"]').length;
            const root = document.querySelector('#root') || document.body;
            const rootTextLen = (root ? root.innerText : '').length;
            const rootHtml = root ? root.innerHTML : '';
            const rootHtmlLen = rootHtml.length;
            const elOuterHtml = el ? (el.outerHTML || '') : '';
            const nonSelfHtml = elOuterHtml
                ? rootHtml.replace(elOuterHtml, '__QA_SELF__')
                : rootHtml;
            const descId = el ? el.getAttribute('aria-describedby') : '';
            const descEl = descId ? document.getElementById(descId) : null;
            const descText = descEl ? (descEl.innerText || '').trim() : '';
            const title = el ? (el.getAttribute('title') || '').trim() : '';
            const disabledReason = el ? (el.getAttribute('data-disabled-reason') || '').trim() : '';
            const alertText = Array.from(
                document.querySelectorAll(
                    '[role="alert"], [role="status"], [aria-live="polite"], [aria-live="assertive"]'
                )
            )
                .map((n) => (n.innerText || '').trim())
                .filter(Boolean)
                .join(' | ');
            const interactiveCount = document.querySelectorAll(
                'button, input, textarea, select, a, [role="dialog"], [role="menu"]'
            ).length;
            return {
                disabled: el
                    ? (Boolean(el.disabled) || el.getAttribute('aria-disabled') === 'true')
                    : false,
                title,
                descText,
                disabledReason,
                alertText,
                ariaPressed: el ? el.getAttribute('aria-pressed') : null,
                ariaExpanded: el ? el.getAttribute('aria-expanded') : null,
                ariaSelected: el ? el.getAttribute('aria-selected') : null,
                className: el ? String(el.className || '') : '',
                dialogs,
                menus,
                rootTextLen,
                rootHtmlLen,
                nonSelfHtmlLen: nonSelfHtml.length,
                nonSelfHtmlSample: nonSelfHtml.slice(0, 4096),
                interactiveCount,
                focusMovedElsewhere: Boolean(
                    active && active !== document.body && el && active !== el
                ),
                elHtmlSample: rootHtml.slice(0, 4096),
            };
        }"""
    )

    url_changed = after_url != url_before
    attrs_changed = (
        before.get("ariaPressed") != after.get("ariaPressed")
        or before.get("ariaExpanded") != after.get("ariaExpanded")
        or before.get("ariaSelected") != after.get("ariaSelected")
    )
    overlay_changed = (
        before.get("dialogs") != after.get("dialogs")
        or before.get("menus") != after.get("menus")
        or before.get("interactiveCount") != after.get("interactiveCount")
    )
    non_self_dom_changed = (
        before.get("rootTextLen") != after.get("rootTextLen")
        or before.get("nonSelfHtmlLen") != after.get("nonSelfHtmlLen")
        or before.get("nonSelfHtmlSample") != after.get("nonSelfHtmlSample")
    )
    dom_changed = non_self_dom_changed or (
        before.get("rootHtmlLen") != after.get("rootHtmlLen")
        or before.get("elHtmlSample") != after.get("elHtmlSample")
    )
    focus_moved = bool(after.get("focusMovedElsewhere", False))
    network_fired = len(requests_fired) > 0

    became_disabled = not bool(before.get("disabled", False)) and bool(after.get("disabled", False))
    if became_disabled:
        has_explanation = bool(
            after.get("disabledReason")
            or after.get("descText")
            or (after.get("title") and after.get("title") != before.get("title"))
            or (after.get("alertText") and after.get("alertText") != before.get("alertText"))
        )
        if not (
            has_explanation
            or url_changed
            or attrs_changed
            or overlay_changed
            or non_self_dom_changed
            or focus_moved
            or network_fired
        ):
            return (
                "blocked",
                "enabled",
                "self_disabled_unexplained",
                f"Control {selector} became disabled/aria-disabled upon click without explanation "
                "or observable state transition",
            )

    effects: list[str] = []
    if url_changed:
        effects.append("url_changed")
    if attrs_changed:
        effects.append("aria_state_changed")
    if overlay_changed:
        effects.append("overlay_or_controls_changed")
    if dom_changed:
        effects.append("dom_mutated")
    if focus_moved:
        effects.append("focus_moved_to_target")
    if network_fired:
        effects.append(f"network_requests:{len(requests_fired)}")

    if not effects:
        return (
            "blocked",
            "enabled",
            "silent_noop",
            f"Silent no-op control {selector}: click produced zero DOM, ARIA, dialog, "
            "focus, navigation, or network effect",
        )

    return ("covered", "enabled", "+".join(effects), None)


def _resolve_repo_sha(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return "unknown"


def _compute_by_module(items: Sequence[ControlInventoryItem]) -> dict[str, dict[str, int]]:
    by_mod: dict[str, dict[str, int]] = {}
    for item in items:
        bucket = by_mod.setdefault(
            item.module,
            {"total": 0, "covered": 0, "blocked": 0, "pending": 0, "out_of_scope": 0},
        )
        bucket["total"] += 1
        bucket[item.coverage_status] += 1
    return by_mod


async def _enumerate_live_dom_controls(page: Page) -> list[dict[str, Any]]:
    raw = await page.evaluate(
        """() => {
            const nodes = Array.from(document.querySelectorAll(
                'button, input, textarea, select, a[href], [role="button"], [role="tab"], '
                + '[role="menuitem"], [role="switch"], [role="checkbox"]'
            ));
            const out = [];
            for (let idx = 0; idx < nodes.length; idx++) {
                const el = nodes[idx];
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden') continue;
                const rect = el.getBoundingClientRect();
                if (rect.width <= 0 && rect.height <= 0) continue;

                const tag = el.tagName.toLowerCase();
                const ariaLabel = (el.getAttribute('aria-label') || '').trim();
                const title = (el.getAttribute('title') || '').trim();
                const placeholder = (el.getAttribute('placeholder') || '').trim();
                const text = (el.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 80);
                const id = (el.id || '').trim();
                const testId = (el.getAttribute('data-testid') || '').trim();
                const role = (el.getAttribute('role') || '').trim().toLowerCase() || (
                    tag === 'textarea' || tag === 'input' ? 'textbox'
                    : tag === 'select' ? 'combobox'
                    : tag === 'a' ? 'link'
                    : 'button'
                );
                const accessibleName = ariaLabel || title || placeholder || text || testId || id;
                const esc = (s) => s.replace(/"/g, '\\"');
                let selector = '';
                if (id) selector = '#' + CSS.escape(id);
                else if (testId) selector = `[data-testid="${esc(testId)}"]`;
                else if (ariaLabel) selector = `${tag}[aria-label="${esc(ariaLabel)}"]`;
                else if (placeholder) selector = `${tag}[placeholder="${esc(placeholder)}"]`;
                else if (title) selector = `${tag}[title="${esc(title)}"]`;
                else {
                    const attrName = 'data-qa-probe-idx';
                    el.setAttribute(attrName, String(idx));
                    selector = `[${attrName}="${idx}"]`;
                }
                out.push({
                    tag,
                    role,
                    id,
                    testId,
                    ariaLabel,
                    title,
                    placeholder,
                    text,
                    accessibleName,
                    selector,
                    disabled: Boolean(el.disabled) || el.getAttribute('aria-disabled') === 'true',
                    tabIndex: el.tabIndex,
                    inAside: Boolean(el.closest('aside')),
                    inHeader: Boolean(el.closest('header')),
                });
            }
            return out;
        }"""
    )
    return raw if isinstance(raw, list) else []


def _infer_live_module(ctrl: dict[str, Any]) -> str:
    name = str(ctrl.get("accessibleName", "")).lower()
    if ctrl.get("inAside"):
        if any(tok in name for tok in ("settings", "connect apps", "keyboard")):
            return "settings"
        if "memory" in name:
            return "memory"
        return "roster"
    if ctrl.get("inHeader"):
        if "computer" in name:
            return "computer"
        if "page" in name:
            return "artifacts"
        return "chat"
    if any(tok in name for tok in ("composer", "send", "attach", "voice", "model", "thinking")):
        return "chat"
    return "shell"


async def _run_studio_interactive_probes(
    page: Page,
    *,
    output_dir: Path,
    capture_screenshots: bool,
) -> tuple[
    list[ControlInventoryItem],
    list[str],
    list[str],
    list[ScreenshotCheckpoint],
    bool,
]:
    """Exercise Studio modals, Settings tabs, and Inspector tabs safely (single-fire)."""
    probed_items: list[ControlInventoryItem] = []
    focus_defects: list[str] = []
    silent_noops: list[str] = []
    screenshots: list[ScreenshotCheckpoint] = []

    modal_triggers: tuple[tuple[str, str, str, str], ...] = (
        ("settings", 'aside button[aria-label="Settings"]', "Settings", "CB-08"),
        ("shell", 'aside button[aria-label="Keyboard shortcuts"]', "Keyboard shortcuts", "CB-00"),
        ("roster", 'aside button[aria-label="Hidden bots"]', "Hidden bots", "CB-04"),
        ("settings", 'aside button[aria-label="Connect apps"]', "Connect apps", "CB-08"),
        ("memory", 'aside button[aria-label="Memory"]', "Memory", "CB-08"),
        (
            "shell",
            'button[aria-label="Search and commands"], button:has-text("Search or jump")',
            "Command palette",
            "CB-04",
        ),
    )

    for module, selector, label, case_id in modal_triggers:
        loc = page.locator(selector).first
        if await loc.count() == 0 or not await loc.is_visible():
            continue
        ok, defect = await probe_modal_focus_cycle(page, selector)
        if not ok and defect:
            focus_defects.append(defect)
        probed_items.append(
            ControlInventoryItem(
                control_id=f"live:{module}:{_slugify(label)}",
                module=module,
                route="/app",
                role="button",
                accessible_name=label,
                selector=selector,
                initial_state="enabled",
                post_state="modal_opened_trapped_and_restored" if ok else "focus_defect",
                precondition="Sidebar/shell visible",
                observable_effect=(
                    "Opens modal dialog, traps Tab/Shift+Tab, closes on Escape, restores focus"
                    if ok
                    else (defect or "Focus defect")
                ),
                keyboard_accessible=ok,
                repeatable=True,
                test_case_id=case_id,
                coverage_status="covered" if ok else "blocked",
                blocked_reason=None if ok else (defect or "Modal focus cycle failed"),
            )
        )

    # Probe Settings 5 tabs and capture System & Tasks checkpoint.
    settings_btn = page.locator('aside button[aria-label="Settings"]').first
    if await settings_btn.count() > 0 and await settings_btn.is_visible():
        await settings_btn.click(timeout=3000)
        dialog = page.locator('[role="dialog"][aria-modal="true"]').first
        await dialog.wait_for(state="visible", timeout=5000)
        for tab_name in ("General", "Computer", "Vault", "Usage", "System & Tasks"):
            tab_btn = dialog.get_by_role("button", name=tab_name).first
            if await tab_btn.count() > 0 and await tab_btn.is_visible():
                await tab_btn.click(timeout=3000)
                probed_items.append(
                    ControlInventoryItem(
                        control_id=f"live:settings:tab_{_slugify(tab_name)}",
                        module="settings",
                        route="/app#modal:settings",
                        role="button",
                        accessible_name=f"Settings tab: {tab_name}",
                        selector=f'[role="dialog"] button:has-text("{tab_name}")',
                        initial_state="enabled",
                        post_state="settings_tab_active",
                        precondition="SettingsDialog open",
                        observable_effect=f"Switches Settings panel to {tab_name}",
                        keyboard_accessible=True,
                        repeatable=True,
                        test_case_id="CB-08",
                        coverage_status="covered",
                        blocked_reason=None,
                    )
                )
        if capture_screenshots:
            screenshots.append(
                await capture_screenshot_checkpoint(
                    page,
                    output_dir=output_dir,
                    case_id="QA-2",
                    label="settings_system_tasks",
                )
            )
        await page.keyboard.press("Escape")
        await dialog.wait_for(state="hidden", timeout=5000)

    # Probe '+' New menu -> CreateBotModal & CreateChannelModal (check disabled submit only).
    new_menu_btn = page.locator('button[aria-label="New bot, group chat, or section"]').first
    if await new_menu_btn.count() > 0 and await new_menu_btn.is_visible():
        for menu_label, modal_btn_name in (
            ("New bot", "Create bot"),
            ("New group chat", "Create group chat"),
        ):
            await new_menu_btn.click(timeout=3000)
            menu_pat = re.compile(rf"^{re.escape(menu_label)}")
            menu_item = page.locator("button").filter(has_text=menu_pat).first
            if await menu_item.count() > 0 and await menu_item.is_visible():
                await menu_item.click(timeout=3000)
                dialog = page.locator('[role="dialog"][aria-modal="true"]').first
                await dialog.wait_for(state="visible", timeout=5000)
                submit_btn = dialog.get_by_role("button", name=modal_btn_name).first
                if await submit_btn.count() > 0:
                    is_disabled = await submit_btn.is_disabled()
                    post_st = (
                        "disabled_when_required_fields_empty" if is_disabled else "enabled"
                    )
                    probed_items.append(
                        ControlInventoryItem(
                            control_id=f"live:roster:{_slugify(modal_btn_name)}",
                            module="roster",
                            route="/app#modal:create",
                            role="button",
                            accessible_name=modal_btn_name,
                            selector=f'[role="dialog"] button:has-text("{modal_btn_name}")',
                            initial_state="disabled" if is_disabled else "enabled",
                            post_state=post_st,
                            precondition=f"{menu_label} modal open with empty name",
                            observable_effect="Submit disabled until required fields valid",
                            keyboard_accessible=True,
                            repeatable=False,
                            test_case_id="CB-04",
                            coverage_status="blocked" if is_disabled else "pending",
                            blocked_reason=(
                                f"Disabled until required fields for {modal_btn_name!r} are filled"
                            ),
                        )
                    )
                await page.keyboard.press("Escape")
                await dialog.wait_for(state="hidden", timeout=5000)

    # Probe Inspector tabs + Computer sub-tabs + composer layout while Inspector open.
    composer_with_inspector_intact = True
    insp_btn = page.locator('button[aria-label="Toggle inspector panel"]').first
    if await insp_btn.count() > 0 and await insp_btn.is_visible():
        await insp_btn.click(timeout=3000)
        tablist = page.locator('[role="tablist"][aria-label="Inspector tabs"]').first
        if await tablist.count() > 0:
            await tablist.wait_for(state="visible", timeout=5000)
            for tab_name, mod_name, case_id in (
                ("Details", "routines", "CB-08"),
                ("Library", "artifacts", "CB-05"),
                ("Computer", "computer", "CB-06"),
            ):
                tab_loc = tablist.get_by_role("tab", name=tab_name).first
                if await tab_loc.count() > 0:
                    await tab_loc.click(timeout=3000)
                    selected = await tab_loc.get_attribute("aria-selected")
                    probed_items.append(
                        ControlInventoryItem(
                            control_id=f"live:{mod_name}:inspector_tab_{_slugify(tab_name)}",
                            module=mod_name,
                            route=f"/app#inspector:{tab_name.lower()}",
                            role="tab",
                            accessible_name=f"Inspector tab: {tab_name}",
                            selector=f'[role="tablist"] [role="tab"]:has-text("{tab_name}")',
                            initial_state="enabled",
                            post_state=f"aria-selected={selected}",
                            precondition="Inspector panel open",
                            observable_effect=f"Activates {tab_name} inspector view",
                            keyboard_accessible=True,
                            repeatable=True,
                            test_case_id=case_id,
                            coverage_status="covered" if selected == "true" else "blocked",
                            blocked_reason=(
                                None
                                if selected == "true"
                                else f"Tab {tab_name!r} did not set aria-selected='true'"
                            ),
                        )
                    )
            for sub_name in ("Terminal", "Files", "Screen"):
                sub_sel = f'button:has(span:text-is("{sub_name}"))'
                sub_btn = page.locator(sub_sel).first
                if await sub_btn.count() > 0 and await sub_btn.is_visible():
                    status, init_st, post_st, blk_reason = await probe_control_state_transition(
                        page,
                        sub_sel,
                        allow_mutation=False,
                    )
                    if post_st == "silent_noop":
                        silent_noops.append(sub_name)
                    probed_items.append(
                        ControlInventoryItem(
                            control_id=f"live:computer:subtab_{_slugify(sub_name)}",
                            module="computer",
                            route="/app#inspector:computer",
                            role="button",
                            accessible_name=f"Computer sub-tab: {sub_name}",
                            selector=sub_sel,
                            initial_state=init_st,
                            post_state=post_st,
                            precondition="Computer inspector tab open",
                            observable_effect=f"Switches Computer sub-tab to {sub_name}",
                            keyboard_accessible=True,
                            repeatable=True,
                            test_case_id="CB-06",
                            coverage_status=status,
                            blocked_reason=blk_reason,
                        )
                    )
            composer_with_inspector_intact, _ = await check_composer_single_row(page)
            if capture_screenshots:
                screenshots.append(
                    await capture_screenshot_checkpoint(
                        page,
                        output_dir=output_dir,
                        case_id="QA-2",
                        label="inspector_computer",
                    )
                )
        # Close inspector cleanly so main workspace returns to baseline state.
        if await insp_btn.is_visible():
            await insp_btn.click(timeout=3000)

    return (
        probed_items,
        focus_defects,
        silent_noops,
        screenshots,
        composer_with_inspector_intact,
    )


async def _run_discovery_on_page(
    page: Page,
    *,
    app_url: str,
    output_dir: Path,
    campaign_id: str,
    repo_root: Path,
    allow_mutation: bool,
    capture_screenshots: bool,
) -> tuple[
    CoverageReport,
    list[ScreenshotCheckpoint],
    list[str],
    list[str],
    list[str],
    bool,
    str,
    bool,
]:
    await page.goto(app_url, wait_until="domcontentloaded")
    with contextlib.suppress(Exception):
        await page.locator(
            'textarea[aria-label="Message composer"], #root button, #root input, '
            '#root textarea, button'
        ).first.wait_for(state="visible", timeout=15000)
    await page.wait_for_timeout(200)

    screenshots: list[ScreenshotCheckpoint] = []
    if capture_screenshots:
        screenshots.append(
            await capture_screenshot_checkpoint(
                page,
                output_dir=output_dir,
                case_id="QA-2",
                label="app_initial",
                repo_root=repo_root,
            )
        )

    is_studio = (
        await page.locator('aside button[aria-label="Settings"]').count() > 0
        and await page.locator('textarea[aria-label="Message composer"]').count() > 0
    )

    local_remote_visible, local_remote_location = await check_local_remote_indicator(page)
    composer_intact, _ = await check_composer_single_row(page)

    live_dom_controls = await _enumerate_live_dom_controls(page)
    items: list[ControlInventoryItem] = []
    silent_noops: list[str] = []
    focus_defects: list[str] = []
    missing_labels: list[str] = []
    probed_selectors: set[str] = set()
    probed_names: set[tuple[str, str]] = set()

    if is_studio:
        (
            studio_items,
            studio_focus_defects,
            studio_noops,
            studio_shots,
            insp_composer_intact,
        ) = await _run_studio_interactive_probes(
            page,
            output_dir=output_dir,
            capture_screenshots=capture_screenshots,
        )
        items.extend(studio_items)
        focus_defects.extend(studio_focus_defects)
        silent_noops.extend(studio_noops)
        screenshots.extend(studio_shots)
        composer_intact = composer_intact and insp_composer_intact
        for item in studio_items:
            probed_selectors.add(item.selector)
            if item.accessible_name:
                probed_names.add((item.module, item.accessible_name.lower()))

    # Probe remaining visible live DOM controls (single-fire).
    safe_skip_in_studio = {
        "toggle inspector panel",
        "open bot computer",
        "create new interactive page",
        "new bot, group chat, or section",
        "settings",
        "keyboard shortcuts",
        "hidden bots",
        "connect apps",
        "memory",
        "search and commands",
        "search or jump…",
    }

    for idx, ctrl in enumerate(live_dom_controls):
        sel = str(ctrl["selector"])
        name = str(ctrl.get("accessibleName", "")).strip()
        role = str(ctrl.get("role", "button"))
        module = _infer_live_module(ctrl) if is_studio else "shell"
        if not name:
            missing_labels.append(sel)
        if sel in probed_selectors or (name and (module, name.lower()) in probed_names):
            continue

        if is_studio and name.lower() in safe_skip_in_studio:
            continue

        status, init_st, post_st, blk_reason = await probe_control_state_transition(
            page,
            sel,
            allow_mutation=allow_mutation,
        )
        if post_st == "silent_noop":
            silent_noops.append(name or sel)
        if status == "covered":
            probed_selectors.add(sel)
            if name:
                probed_names.add((module, name.lower()))

        items.append(
            ControlInventoryItem(
                control_id=f"live:{module}:{_slugify(name or sel)}:{idx}",
                module=module,
                route="/app",
                role=role,
                accessible_name=name,
                selector=sel,
                initial_state=init_st,
                post_state=post_st,
                precondition="Active /app view",
                observable_effect=post_st if status == "covered" else (blk_reason or post_st),
                keyboard_accessible=int(ctrl.get("tabIndex", 0)) >= 0,
                repeatable=not any(
                    tok in name.lower() for tok in (*_DESTRUCTIVE_KEYWORDS, *_CLICK_MUTATE_KEYWORDS)
                ),
                test_case_id="CB-00",
                coverage_status=status,
                blocked_reason=blk_reason,
            )
        )

    # Merge static React TSX inventory when running against full ControlBot Studio.
    if is_studio:
        static_specs = discover_static_controls(repo_root / "frontend" / "src")
        for spec in static_specs:
            if "missing_accessible_label" in spec.a11y_gaps:
                missing_labels.append(f"{spec.source_file}:{spec.line_number} ({spec.selector})")
            if "missing_modal_focus_trap" in spec.a11y_gaps:
                focus_defects.append(
                    f"{spec.source_file}:{spec.line_number} missing Tab focus trap"
                )

            already_probed = spec.selector in probed_selectors or (
                bool(spec.accessible_name)
                and (spec.module, spec.accessible_name.lower()) in probed_names
            )
            if already_probed:
                continue

            if "missing_modal_focus_trap" in spec.a11y_gaps:
                cov_status: CoverageStatus = "blocked"
                reason = (
                    "Static inspection detected modal focus-trap defect "
                    f"({', '.join(spec.a11y_gaps)})"
                )
            elif "missing_accessible_label" in spec.a11y_gaps:
                cov_status = "pending"
                reason = (
                    f"Not exercised in CB-00 smoke discovery ({spec.precondition}; "
                    "also flagged for missing_accessible_label)"
                )
            else:
                cov_status = "pending"
                reason = f"Deferred to scenario {spec.test_case_id or 'CB-00'}: {spec.precondition}"

            items.append(
                ControlInventoryItem(
                    control_id=spec.control_id,
                    module=spec.module,
                    route=spec.route,
                    role=spec.role,
                    accessible_name=spec.accessible_name,
                    selector=spec.selector,
                    initial_state="static_declared",
                    post_state="unprobed",
                    precondition=spec.precondition,
                    observable_effect="",
                    keyboard_accessible="missing_modal_focus_trap" not in spec.a11y_gaps,
                    repeatable=spec.repeatable,
                    test_case_id=spec.test_case_id,
                    coverage_status=cov_status,
                    blocked_reason=reason,
                )
            )

    if capture_screenshots and (silent_noops or focus_defects):
        screenshots.append(
            await capture_screenshot_checkpoint(
                page,
                output_dir=output_dir,
                case_id="QA-2",
                label="discovery_defects",
                is_error_state=True,
                repo_root=repo_root,
            )
        )

    covered_count = sum(1 for item in items if item.coverage_status == "covered")
    blocked_count = sum(1 for item in items if item.coverage_status == "blocked")
    pending_count = sum(1 for item in items if item.coverage_status == "pending")
    out_of_scope_count = sum(1 for item in items if item.coverage_status == "out_of_scope")

    for item in items:
        if item.coverage_status != "covered" and not (item.blocked_reason or "").strip():
            raise ValueError(
                f"Non-covered item {item.control_id!r} ({item.coverage_status}) "
                "missing blocked_reason"
            )

    report = CoverageReport(
        campaign_id=campaign_id,
        generated_at=utc_now(),
        repo_sha=_resolve_repo_sha(repo_root),
        total_controls=len(items),
        covered_count=covered_count,
        blocked_count=blocked_count,
        pending_count=pending_count,
        out_of_scope_count=out_of_scope_count,
        by_module=_compute_by_module(items),
        items=items,
    )
    return (
        report,
        screenshots,
        silent_noops,
        focus_defects,
        sorted(set(missing_labels)),
        local_remote_visible,
        local_remote_location,
        composer_intact,
    )


async def run_live_discovery(
    *,
    output_dir: Path,
    base_url: str | None = None,
    campaign_id: str | None = None,
    repo_root: Path | None = None,
    token: str | None = None,
    allow_mutation: bool = False,
    capture_screenshots: bool = True,
    user_data_dir: Path | None = None,
) -> DiscoveryProbeResult:
    """Run live Playwright + static UI control discovery and write `coverage.json`."""
    resolved_repo = (repo_root or _REPO_ROOT).resolve()
    safe_output = assert_safe_mutation_path(output_dir, repo_root=resolved_repo)
    safe_output.mkdir(parents=True, exist_ok=True)
    if base_url is not None:
        assert_not_live_target(base_url)

    resolved_campaign = campaign_id or f"qa-discover-{utc_now().strftime('%Y%m%dT%H%M%SZ')}"

    async def _probe_url(target_base: str, pw_dir: Path | None) -> DiscoveryProbeResult:
        clean_base = target_base.rstrip("/")
        qs = f"?{urlencode({'token': token})}" if token else ""
        app_url = f"{clean_base}/app{qs}"
        async with StrictPlaywrightSession(user_data_dir=pw_dir) as session:
            (
                report,
                shots,
                noops,
                f_defects,
                missing_lbls,
                lr_visible,
                lr_loc,
                comp_intact,
            ) = await _run_discovery_on_page(
                session.page,
                app_url=app_url,
                output_dir=safe_output,
                campaign_id=resolved_campaign,
                repo_root=resolved_repo,
                allow_mutation=allow_mutation,
                capture_screenshots=capture_screenshots,
            )
            console_errs = list(session.console_errors)
            page_errs = list(session.page_errors)
            http_errs = [f"{code} {url}" for code, url in session.http_errors]
            ext_reqs = list(session.external_requests)

        cov_payload = redact_payload_m3(json.loads(report.model_dump_json()))
        if contains_unredacted_secret_m3(cov_payload):
            raise ValueError("Refusing to write coverage.json containing unredacted secret.")
        cov_path = safe_output / "coverage.json"
        tmp_cov = cov_path.with_suffix(".json.tmp")
        tmp_cov.write_text(
            json.dumps(cov_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp_cov.replace(cov_path)

        return DiscoveryProbeResult(
            coverage=report,
            coverage_path=str(cov_path),
            screenshots=shots,
            silent_noop_controls=noops,
            focus_defects=f_defects,
            missing_label_controls=missing_lbls,
            local_remote_indicator_visible=lr_visible,
            local_remote_location=lr_loc,
            composer_layout_intact=comp_intact,
            console_errors=console_errs,
            page_errors=page_errs,
            http_errors=http_errs,
            external_requests=ext_reqs,
        )

    if base_url is not None:
        return await _probe_url(base_url, user_data_dir)

    with _frontend_dist_shared_lock(resolved_repo), IsolatedLabServer(
        repo_root=resolved_repo, web_token=token
    ) as lab:
        return await _probe_url(
            lab.base_url,
            user_data_dir or lab.workspace.playwright_user_data_dir,
        )


@contextlib.contextmanager
def _frontend_dist_shared_lock(repo_root: Path) -> Iterator[None]:
    """Coordinate with `baseline.py` exclusive frontend builds via shared flock."""
    lock_path: Path | None = None
    git_entry = repo_root / ".git"
    if git_entry.exists():
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--git-common-dir"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            common_dir = Path(proc.stdout.strip())
            if not common_dir.is_absolute():
                common_dir = (repo_root / common_dir).resolve()
            if common_dir.is_dir():
                lock_path = common_dir / "qa_frontend_build.lock"
    if lock_path is None:
        yield
        return
    with lock_path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _run_coro_sync[T](coro: Coroutine[Any, Any, T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def discover_controls(
    *,
    output_dir: Path,
    base_url: str | None = None,
    campaign_id: str | None = None,
    repo_root: Path | None = None,
    token: str | None = None,
    allow_mutation: bool = False,
    capture_screenshots: bool = True,
    user_data_dir: Path | None = None,
) -> DiscoveryProbeResult:
    """Synchronous wrapper for `run_live_discovery`."""
    return _run_coro_sync(
        run_live_discovery(
            output_dir=output_dir,
            base_url=base_url,
            campaign_id=campaign_id,
            repo_root=repo_root,
            token=token,
            allow_mutation=allow_mutation,
            capture_screenshots=capture_screenshots,
            user_data_dir=user_data_dir,
        )
    )


__all__ = [
    "DiscoveryProbeResult",
    "StaticControlSpec",
    "discover_controls",
    "discover_static_controls",
    "probe_control_state_transition",
    "probe_modal_focus_cycle",
    "run_live_discovery",
]
