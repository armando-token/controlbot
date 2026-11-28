"""CB-01 scenario runner: simple chat turn, SSE presence, thread persistence & error clarity."""

from __future__ import annotations

import contextlib
import html
import re
import uuid
from collections.abc import Callable
from typing import Any

from playwright.async_api import Page
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    TurnOutcome,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import (
    check_composer_single_row,
    check_local_remote_indicator,
    evaluate_error_actionability,
    measure_ux_action,
)

_HR_LINE_RE = re.compile(r"^(?:[-*_]\s*){3,}$")
_TABLE_SEP_RE = re.compile(r"^\|?\s*:?-{1,}:?\s*(?:\|\s*:?-{1,}:?\s*)+\|?$")
_TABLE_SEP_SINGLE_RE = re.compile(r"^\|(?:\s*:?-{1,}:?\s*\|)+$")


_ASCII_PUNCT = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_AUTOLINK_URI_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9+.-]{1,31}:[^\s<>]+)>")
_AUTOLINK_EMAIL_RE = re.compile(r"<([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>")
_REF_LINK_DEF_RE = re.compile(r"^\[(?!\^)([^\]]+)\]:\s+\S+")
_FOOTNOTE_DEF_RE = re.compile(r"^\[\^([^\]\s]+)\]:(?:\s|$)")
_FENCE_OPEN_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
_FENCE_CLOSE_RE = re.compile(r"^(`{3,}|~{3,})\s*$")
_ATX_HEADING_RE = re.compile(r"^#{1,6}(?:\s+(.*)|)$")


def _strip_bq_prefix(line: str, *, max_markers: int | None = None) -> tuple[int, str]:
    count = 0
    rest = line
    while rest.startswith(">") and (max_markers is None or count < max_markers):
        count += 1
        rest = rest[1:].lstrip()
    return count, rest


def _normalize_ref_label(label: str) -> str:
    return " ".join(label.split()).casefold()


def _stash_code_spans_and_escapes(text: str, stash: Callable[[str], str]) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            if i + 1 < n and text[i + 1] in _ASCII_PUNCT:
                out.append(stash(text[i + 1]))
                i += 2
            else:
                out.append(ch)
                i += 1
        elif ch == "`":
            run_len = 1
            while i + run_len < n and text[i + run_len] == "`":
                run_len += 1
            j = i + run_len
            close_idx = -1
            while j < n:
                if text[j] == "`":
                    close_len = 1
                    while j + close_len < n and text[j + close_len] == "`":
                        close_len += 1
                    if close_len == run_len:
                        close_idx = j
                        break
                    j += close_len
                else:
                    j += 1
            if close_idx != -1:
                content = text[i + run_len : close_idx]
                if (
                    len(content) >= 2
                    and content.startswith(" ")
                    and content.endswith(" ")
                    and content.strip(" ")
                ):
                    content = content[1:-1]
                out.append(stash(content))
                i = close_idx + run_len
            else:
                out.append("`" * run_len)
                i += run_len
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _strip_inline_dest_constructs(line: str, *, is_image: bool) -> str:
    prefix = "![" if is_image else "["
    plen = len(prefix)
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        if line.startswith(prefix, i) and (is_image or i == 0 or line[i - 1] != "!"):
            j = i + plen
            bracket_depth = 1
            close_bracket = -1
            while j < n:
                if line[j] == "[":
                    bracket_depth += 1
                elif line[j] == "]":
                    bracket_depth -= 1
                    if bracket_depth == 0:
                        close_bracket = j
                        break
                j += 1
            if close_bracket != -1 and close_bracket + 1 < n and line[close_bracket + 1] == "(":
                k = close_bracket + 2
                paren_depth = 1
                while k < n and paren_depth > 0:
                    if line[k] == "(":
                        paren_depth += 1
                    elif line[k] == ")":
                        paren_depth -= 1
                    k += 1
                if paren_depth == 0:
                    if not is_image:
                        out.append(line[i + plen : close_bracket])
                    i = k
                    continue
        out.append(line[i])
        i += 1
    return "".join(out)


def _split_table_row_cells(line: str) -> list[str]:
    """Split a Markdown table row on unescaped `|` outside inline code spans."""
    cells: list[str] = []
    cur: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\":
            if i + 1 < n and line[i + 1] in _ASCII_PUNCT:
                cur.append(line[i : i + 2])
                i += 2
            else:
                cur.append(ch)
                i += 1
        elif ch == "`":
            run_len = 1
            while i + run_len < n and line[i + run_len] == "`":
                run_len += 1
            j = i + run_len
            close_idx = -1
            while j < n:
                if line[j] == "`":
                    close_len = 1
                    while j + close_len < n and line[j + close_len] == "`":
                        close_len += 1
                    if close_len == run_len:
                        close_idx = j
                        break
                    j += close_len
                else:
                    j += 1
            if close_idx != -1:
                cur.append(line[i : close_idx + run_len])
                i = close_idx + run_len
            else:
                cur.append("`" * run_len)
                i += run_len
        elif ch == "|":
            cells.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(ch)
            i += 1
    cells.append("".join(cur))
    return cells


def _strip_inline_markdown(
    text: str,
    *,
    defined_refs: frozenset[str] | set[str] | None = None,
    defined_footnotes: frozenset[str] | set[str] | None = None,
    footnote_numbers: dict[str, int] | None = None,
) -> str:
    placeholders: list[str] = []

    def _stash(value: str) -> str:
        token = f"\x00MDPH{len(placeholders)}\x00"
        placeholders.append(value)
        return token

    # 1 & 2. Scan left-to-right for backslash-escaped punctuation and inline code spans
    # so escaped backticks (\`...\` ) do not masquerade as inline code spans.
    line = _stash_code_spans_and_escapes(text, _stash)
    # 3. Strip Markdown images and links (including balanced parens in URLs), keeping link text.
    line = _strip_inline_dest_constructs(line, is_image=True)
    if defined_refs:
        line = re.sub(
            r"!\[([^\]]*)\]\[([^\]]*)\]",
            lambda m: ""
            if _normalize_ref_label(m.group(2) or m.group(1)) in defined_refs
            else m.group(0),
            line,
        )
    line = _strip_inline_dest_constructs(line, is_image=False)
    if defined_refs:
        line = re.sub(
            r"(?<!!)\[([^\]]+)\]\[([^\]]*)\]",
            lambda m: m.group(1)
            if _normalize_ref_label(m.group(2) or m.group(1)) in defined_refs
            else m.group(0),
            line,
        )
        line = re.sub(
            r"!\[([^\]]+)\](?![\[(])",
            lambda m: "" if _normalize_ref_label(m.group(1)) in defined_refs else m.group(0),
            line,
        )
        line = re.sub(
            r"(?<!!)\[([^\]]+)\](?![\[(])",
            lambda m: m.group(1)
            if _normalize_ref_label(m.group(1)) in defined_refs
            else m.group(0),
            line,
        )
    if defined_footnotes:

        def _replace_footnote(m: re.Match[str]) -> str:
            label = _normalize_ref_label(m.group(1))
            if label not in defined_footnotes:
                return m.group(0)
            if footnote_numbers is not None:
                return str(footnote_numbers.setdefault(label, len(footnote_numbers) + 1))
            return m.group(1)

        line = re.sub(r"(?<!!)\[\^([^\]\s]+)\](?![\[(])", _replace_footnote, line)
    # 4. Unwrap GFM / CommonMark autolinks (<https://...>, <mailto:...>, <user@host>).
    line = _AUTOLINK_URI_RE.sub(r"\1", line)
    line = _AUTOLINK_EMAIL_RE.sub(r"\1", line)
    # 5. Strip emphasis and GFM strikethrough (both ~single~ and ~~double~~).
    # Per CommonMark, `__` and `_` cannot open/close intraword emphasis, whereas `**`/`*` can.
    for _ in range(2):
        line = re.sub(r"\*\*(?!\s)(.+?)(?<!\s)\*\*", r"\1", line)
        line = re.sub(r"(?<!\w)__(?!\s)(.+?)(?<!\s)__(?!\w)", r"\1", line)
        line = re.sub(r"\*(?!\s|\*)(.+?)(?<!\s|\*)\*", r"\1", line)
        line = re.sub(r"(?<!\w)_(?!\s|_)(.+?)(?<!\s|_)_(?!\w)", r"\1", line)
        line = re.sub(r"(?<!~)(~~?)(?!~|\s)(.+?)(?<!\s|~)\1(?!~)", r"\2", line)
    # 6. Decode HTML character references outside protected inline code spans / escapes.
    line = html.unescape(line)
    # 7. Restore protected inline code spans and escaped punctuation literally.
    for idx, literal in enumerate(placeholders):
        line = line.replace(f"\x00MDPH{idx}\x00", literal)
    return " ".join(line.split()).strip()


def _collect_defined_labels(lines: list[str]) -> tuple[set[str], set[str]]:
    defined_refs: set[str] = set()
    defined_footnotes: set[str] = set()
    fence_char: str | None = None
    fence_len = 0
    fence_bq_depth = 0
    for raw_line in lines:
        line = raw_line.strip()
        if fence_char is not None:
            if fence_bq_depth > 0:
                cur_bq, inner = _strip_bq_prefix(line, max_markers=fence_bq_depth)
                if cur_bq >= fence_bq_depth:
                    close_match = _FENCE_CLOSE_RE.match(inner)
                    if (
                        close_match is not None
                        and close_match.group(1)[0] == fence_char
                        and len(close_match.group(1)) >= fence_len
                    ):
                        fence_char = None
                        fence_len = 0
                        fence_bq_depth = 0
                    continue
                fence_char = None
                fence_len = 0
                fence_bq_depth = 0
            else:
                close_match = _FENCE_CLOSE_RE.match(line)
                if (
                    close_match is not None
                    and close_match.group(1)[0] == fence_char
                    and len(close_match.group(1)) >= fence_len
                ):
                    fence_char = None
                    fence_len = 0
                continue
        bq_depth, line = _strip_bq_prefix(line)
        open_match = _FENCE_OPEN_RE.match(line)
        if open_match is not None:
            marker = open_match.group(1)
            info = open_match.group(2)
            if not (marker[0] == "`" and "`" in info):
                fence_char = marker[0]
                fence_len = len(marker)
                fence_bq_depth = bq_depth
                continue
        fn_match = _FOOTNOTE_DEF_RE.match(line)
        if fn_match is not None:
            defined_footnotes.add(_normalize_ref_label(fn_match.group(1)))
            continue
        ref_match = _REF_LINK_DEF_RE.match(line)
        if ref_match is not None:
            defined_refs.add(_normalize_ref_label(ref_match.group(1)))
    return defined_refs, defined_footnotes


def _collect_defined_ref_labels(lines: list[str]) -> set[str]:
    defined_refs, _ = _collect_defined_labels(lines)
    return defined_refs


def _extract_markdown_match_fragments(raw: str) -> list[str]:
    """Extract visible text fragments from Markdown to match ReactMarkdown + remarkGfm DOM."""
    lines = raw.splitlines()
    defined_refs, defined_footnotes = _collect_defined_labels(lines)
    footnote_numbers: dict[str, int] = {}
    has_table_sep = any(
        _TABLE_SEP_RE.match(_strip_bq_prefix(ln.strip())[1])
        or _TABLE_SEP_SINGLE_RE.match(_strip_bq_prefix(ln.strip())[1])
        for ln in lines
    )
    fragments: list[str] = []
    fence_char: str | None = None
    fence_len = 0
    fence_bq_depth = 0
    for raw_line in lines:
        line = raw_line.strip()
        if fence_char is not None:
            if fence_bq_depth > 0:
                cur_bq, inner = _strip_bq_prefix(line, max_markers=fence_bq_depth)
                if cur_bq >= fence_bq_depth:
                    close_match = _FENCE_CLOSE_RE.match(inner)
                    if (
                        close_match is not None
                        and close_match.group(1)[0] == fence_char
                        and len(close_match.group(1)) >= fence_len
                    ):
                        fence_char = None
                        fence_len = 0
                        fence_bq_depth = 0
                        continue
                    literal_code = " ".join(inner.split()).strip()
                    if literal_code:
                        fragments.append(literal_code[:48].strip())
                    continue
                fence_char = None
                fence_len = 0
                fence_bq_depth = 0
            else:
                close_match = _FENCE_CLOSE_RE.match(line)
                if (
                    close_match is not None
                    and close_match.group(1)[0] == fence_char
                    and len(close_match.group(1)) >= fence_len
                ):
                    fence_char = None
                    fence_len = 0
                    continue
                literal_code = " ".join(line.split()).strip()
                if literal_code:
                    fragments.append(literal_code[:48].strip())
                continue

        if not line:
            continue
        bq_depth, line = _strip_bq_prefix(line)
        if not line:
            continue
        open_match = _FENCE_OPEN_RE.match(line)
        if open_match is not None:
            marker = open_match.group(1)
            info = open_match.group(2)
            if not (marker[0] == "`" and "`" in info):
                fence_char = marker[0]
                fence_len = len(marker)
                fence_bq_depth = bq_depth
                continue
        if _HR_LINE_RE.match(line):
            continue
        if _TABLE_SEP_RE.match(line) or _TABLE_SEP_SINGLE_RE.match(line):
            continue
        if _FOOTNOTE_DEF_RE.match(line) or _REF_LINK_DEF_RE.match(line):
            continue
        if re.match(r"^<!--.*-->$", line):
            continue
        while True:
            prev = line
            _, line = _strip_bq_prefix(line)
            new_line = re.sub(r"^(?:[-*+]|\d+[.)])\s+", "", line)
            if new_line != line:
                line = re.sub(r"^\[[xX\s]\]\s*", "", new_line)
            if line == prev:
                break
        if _HR_LINE_RE.match(line):
            continue
        if _TABLE_SEP_RE.match(line) or _TABLE_SEP_SINGLE_RE.match(line):
            continue
        if _FOOTNOTE_DEF_RE.match(line) or _REF_LINK_DEF_RE.match(line):
            continue
        atx_match = _ATX_HEADING_RE.match(line)
        if atx_match is not None:
            heading_body = (atx_match.group(1) or "").strip()
            line = re.sub(r"(?:^|\s+)#+$", "", heading_body).strip()
        if _HR_LINE_RE.match(line):
            continue
        if not line:
            continue
        is_table_row = "|" in line and (
            line.startswith("|") or line.endswith("|") or has_table_sep
        )
        if is_table_row:
            for cell in _split_table_row_cells(line):
                cleaned_cell = _strip_inline_markdown(
                    cell,
                    defined_refs=defined_refs,
                    defined_footnotes=defined_footnotes,
                    footnote_numbers=footnote_numbers,
                )
                if cleaned_cell:
                    fragments.append(cleaned_cell[:48].strip())
        else:
            cleaned = _strip_inline_markdown(
                line,
                defined_refs=defined_refs,
                defined_footnotes=defined_footnotes,
                footnote_numbers=footnote_numbers,
            )
            if cleaned:
                fragments.append(cleaned[:48].strip())
    return fragments


def _normalize_markdown_for_match(raw: str) -> str:
    """Strip Markdown/GFM syntax and return the first visible fragment matching ReactMarkdown."""
    fragments = _extract_markdown_match_fragments(raw)
    return fragments[0] if fragments else ""


async def _verify_cb01_ui_state(
    page: Page,
    *,
    is_live_agent: bool,
    expected_assistant_text: str,
    expected_approval_title: str,
) -> tuple[bool, bool, str | None]:
    """Verify rendered assistant reply (or error + ApprovalCard in non-agy mode) is visible."""
    if not expected_assistant_text:
        return False, False, "Assistant message text was empty after Markdown normalization."
    try:
        await page.locator(".gb-markdown").get_by_text(
            expected_assistant_text
        ).first.wait_for(state="visible", timeout=10000)
    except PlaywrightTimeoutError:
        kind = "assistant reply" if is_live_agent else "assistant error message"
        return (
            False,
            False,
            f"Rendered {kind} ({expected_assistant_text!r}) not visible in .gb-markdown.",
        )

    if is_live_agent:
        return True, True, None

    try:
        card = page.locator("div.my-2\\.5").filter(has_text=expected_approval_title).first
        await card.get_by_text("Needs approval").wait_for(state="visible", timeout=10000)
    except PlaywrightTimeoutError:
        return (
            True,
            False,
            f"ApprovalCard ({expected_approval_title!r}) not visible in UI.",
        )
    return True, True, None


async def _run_cb01_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "chat"
    marker = f"CB01_{uuid.uuid4().hex[:6]}"
    created_approval_id: str | None = None
    expected_approval_title = ""

    try:
        async with ctx.async_client(timeout=30.0) as aclient:
            if ctx.caps.is_live_agent_target:
                prompt = f"SIMPLE_CHAT_CHECK {marker}"

                async def _send_turn() -> TurnOutcome:
                    return await trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        prompt,
                        timeout=25.0,
                    )

                turn, timing = await measure_ux_action(
                    _send_turn,
                    actions_to_reach=1,
                    cancel_available=True,
                )
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.cancel_available = True
                ctx.message_id = str(turn.user_message.get("id") or "")
                ctx.assertions["user_message_created"] = bool(ctx.message_id)
                active_presence = any(
                    st in {"acknowledging", "working", "thinking"}
                    for st in turn.presence_states
                )
                ctx.assertions["presence_observed"] = bool(turn.presence_states) and active_presence
                ctx.assertions["bot_reply_non_empty"] = bool(turn.reply_text.strip())
                ctx.assertions["bot_reply_done"] = (
                    turn.assistant_message is not None
                    and turn.assistant_message.get("status") == "done"
                )
                expected_text = _normalize_markdown_for_match(turn.reply_text)
            else:
                # Studio without agy: real SSE turn + HITL approval + actionable error check
                expected_approval_title = f"CB-01 simple chat turn {marker}"
                appr_prompt = f"/approval {expected_approval_title}"

                async def _send_approval_turn() -> TurnOutcome:
                    return await trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        appr_prompt,
                        timeout=20.0,
                    )

                turn, timing = await measure_ux_action(
                    _send_approval_turn,
                    actions_to_reach=1,
                    cancel_available=True,
                )
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.cancel_available = True
                ctx.message_id = str(turn.user_message.get("id") or "")
                ctx.assertions["user_message_created"] = bool(ctx.message_id)
                ctx.assertions["presence_observed"] = bool(turn.presence_states)
                ctx.assertions["sse_turn_event_received"] = bool(turn.approvals)
                if turn.approvals:
                    created_approval_id = str(turn.approvals[0].get("id") or "")

                # Also check error actionability when regular chat runs without agy
                err_turn = await trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    f"SIMPLE_CHAT_CHECK {marker}",
                    timeout=15.0,
                )
                err_reply = err_turn.reply_text.strip()
                rendered_reply = re.sub(r"`([^`]+)`", r"\1", err_reply)
                actionable, action_reason = evaluate_error_actionability(rendered_reply)
                ctx.error_actionable = actionable
                ctx.assertions["missing_agy_error_actionable"] = actionable
                if not actionable:
                    ctx.error_notes.append(f"CB-01 error actionability: {action_reason}")
                expected_text = _normalize_markdown_for_match(err_reply)

            # Verify API thread message persistence
            hist_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            ctx.add_request_id(hist_resp)
            msgs = (
                safe_response_dict(hist_resp).get("messages", [])
                if hist_resp.status_code == 200
                else []
            )
            ctx.assertions["api_history_persisted"] = hist_resp.status_code == 200 and any(
                marker in str(m.get("content", "")) for m in msgs
            )

        # Playwright UI thread switching & reload persistence check
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            loc_vis, loc_where = await check_local_remote_indicator(page)
            ctx.local_remote_visible = loc_vis
            ctx.local_remote_location = loc_where
            comp_intact, _ = await check_composer_single_row(page)
            ctx.composer_intact = comp_intact
            ctx.assertions["composer_layout_intact"] = comp_intact

            msg_vis_1, card_vis_1, ui_err_1 = await _verify_cb01_ui_state(
                page,
                is_live_agent=ctx.caps.is_live_agent_target,
                expected_assistant_text=expected_text,
                expected_approval_title=expected_approval_title,
            )
            persisted_ok = msg_vis_1 and card_vis_1
            if ui_err_1:
                ctx.error_notes.append(ui_err_1)

            if persisted_ok:
                await page.locator("aside").get_by_text("ControlBot Ops", exact=True).first.click()
                await page.locator("aside").get_by_text("Chief of Staff", exact=True).first.click()
                msg_vis_2, card_vis_2, ui_err_2 = await _verify_cb01_ui_state(
                    page,
                    is_live_agent=ctx.caps.is_live_agent_target,
                    expected_assistant_text=expected_text,
                    expected_approval_title=expected_approval_title,
                )
                persisted_ok = msg_vis_2 and card_vis_2
                if ui_err_2:
                    ctx.error_notes.append(ui_err_2)

            if persisted_ok:
                await page.reload(wait_until="networkidle", timeout=15000)
                msg_vis_3, card_vis_3, ui_err_3 = await _verify_cb01_ui_state(
                    page,
                    is_live_agent=ctx.caps.is_live_agent_target,
                    expected_assistant_text=expected_text,
                    expected_approval_title=expected_approval_title,
                )
                persisted_ok = msg_vis_3 and card_vis_3
                if ui_err_3:
                    ctx.error_notes.append(ui_err_3)

            if ctx.caps.is_live_agent_target:
                ctx.assertions["ui_assistant_reply_visible"] = persisted_ok
            else:
                ctx.assertions["ui_assistant_error_visible"] = msg_vis_1 and persisted_ok
                ctx.assertions["ui_approval_card_visible"] = card_vis_1 and persisted_ok
            ctx.response_persisted = persisted_ok
            ctx.assertions["ui_thread_switch_and_reload_persisted"] = persisted_ok
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb01_chat", is_error_state=not all_ok)

        ctx.evidence = {
            "thread_id": "thr_bot_chief",
            "marker": marker,
            "live_agent_target": ctx.caps.is_live_agent_target,
        }
        ctx.clarity_notes = (
            "CB-01 chat turn, SSE presence, thread switch & reload persistence verified."
        )
    finally:
        if created_approval_id:
            with contextlib.suppress(Exception), ctx.sync_client() as c:
                c.post(
                    f"/api/v1/approvals/{created_approval_id}/resolve",
                    json={"decision": "deny"},
                )


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-01 scenario."""
    run_coro_sync(_run_cb01_async(ctx))
    return finalize_scenario(ctx)
