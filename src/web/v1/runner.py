"""Async turn execution, multi-bot routing, HITL gating, Policy/Router/Airlock & routines."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import shlex
import smtplib
import sqlite3
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from src.adapters.config import FacilityConfig
from src.adapters.web_search import EgressBlockedError, EgressGuard
from src.contracts.common import InvalidStateTransitionError
from src.contracts.enums import TERMINAL_TASK_STATUSES, BackendMode, TaskStatus
from src.contracts.envelope import (
    AirlockProvenance,
    Lane,
    VerdictState,
    VerifiedResponseMeta,
)
from src.contracts.models import EvidenceRequirements, TaskScope, TaskSpec
from src.engine.airlock import AirlockBlockedError, EvidenceAirlock, build_airlock_provenance
from src.engine.policy_gateway import (
    PolicyGateway,
    PolicyRequest,
    default_studio_policy_set,
    safety_floor,
)
from src.engine.router import LaneRouter, RouteDecision
from src.storage.memory import MemoryAccessContext
from src.web.live_browser import LiveBrowserController
from src.web.protocols import CoordinatorProtocol, TaskSnapshot, maybe_await
from src.web.v1.events import EventBus, scrub_v1_payload, utc_iso_now
from src.web.v1.schemas import MAX_AUTO_REVIEW_RULE_LEN, contains_sensitive_scope_secret
from src.web.v1.store import StoreNotFoundError, WorkspaceStore
from src.web.workspace import (
    _default_local_base_url,
    default_projects_root,
    find_agy_executable,
    resolve_project_dir,
    stream_agy_prompt,
)

logger = logging.getLogger(__name__)

_PAGE_BLOCK_RE = re.compile(
    r":::page\s*\{[^}]*title\s*=\s*(?:\"([^\"]+)\"|'([^']+)')[^}]*\}\s*\n?(.*?)\n?:::",
    re.DOTALL | re.IGNORECASE,
)
_MENTION_RE = re.compile(r"@([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)")


def _extract_inline_mentions(content: str) -> list[str]:
    mentions: list[str] = []
    for raw in _MENTION_RE.findall(content):
        cleaned = raw.rstrip(".,:;!?").lower()
        if cleaned:
            mentions.append(cleaned)
    return mentions
_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+(?:production|prod|all|database|db|files?)\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+(?:table|database|schema)\b", re.IGNORECASE),
    re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
    re.compile(r"\bgit\s+(?:reset\s+--hard|push\s+(?:--force|-f))\b", re.IGNORECASE),
    re.compile(r"\b(?:mkfs|wipefs|shutdown|reboot|kill\s+-9)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+-R\s+777\b", re.IGNORECASE),
    re.compile(r"\b(?:destroy|wipe|format)\s+(?:disk|volume|cluster|production|database)\b", re.I),
)
_RULE_DESTRUCTIVE_HINTS: frozenset[str] = frozenset(
    {"delete", "deleting", "destructive", "remove", "drop", "wipe", "destroy", "shell", "rm"}
)
_STOP_WORDS: frozenset[str] = frozenset(
    {
        "about",
        "action",
        "actions",
        "after",
        "all",
        "allow",
        "always",
        "and",
        "any",
        "are",
        "ask",
        "asking",
        "before",
        "both",
        "but",
        "can",
        "command",
        "commands",
        "confirm",
        "did",
        "each",
        "first",
        "for",
        "from",
        "had",
        "has",
        "have",
        "her",
        "here",
        "his",
        "how",
        "into",
        "its",
        "just",
        "let",
        "may",
        "more",
        "most",
        "never",
        "not",
        "now",
        "off",
        "our",
        "out",
        "own",
        "per",
        "please",
        "routine",
        "routines",
        "she",
        "should",
        "some",
        "such",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "they",
        "thing",
        "things",
        "this",
        "too",
        "two",
        "via",
        "was",
        "way",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "why",
        "will",
        "with",
        "would",
        "yes",
        "yet",
        "you",
        "your",
    }
)
_SHORT_2CHAR_TOKENS: frozenset[str] = frozenset({"go", "do", "rm", "cp", "mv"})
_AUXILIARY_RULE_TOKENS: frozenset[str] = frozenset({"run", "running", "runs"})
_EXACT_RULE_PREFIX = "Allow exact: "
_EXACT_SHA_PREFIX = "Allow exact-sha256: "
_MEMORY_PROMPT_MAX_CHARS = 6000
_PAGE_CONTEXT_MAX_CHARS = 8000


def _parse_cron_field(field: str, min_val: int, max_val: int, *, is_dow: bool = False) -> set[int]:
    values: set[int] = set()
    for part in field.split(","):
        token = part.strip()
        if not token:
            continue
        step = 1
        if "/" in token:
            base, step_str = token.split("/", 1)
            step = int(step_str)
            if step <= 0:
                raise ValueError("Cron step must be positive.")
        else:
            base = token

        if base == "*":
            start, end = min_val, max_val
        elif "-" in base:
            s_str, e_str = base.split("-", 1)
            start, end = int(s_str), int(e_str)
        else:
            val = int(base)
            start, end = val, val

        for num in range(start, end + 1, step):
            normalized = 0 if (is_dow and num == 7) else num
            if min_val <= normalized <= max_val:
                values.add(normalized)
    return values


def cron_matches(expr: str | None, dt: datetime) -> bool:
    """Return True if a standard 5-field cron expression matches dt."""
    if not expr or not expr.strip():
        return False
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    try:
        minutes = _parse_cron_field(parts[0], 0, 59)
        hours = _parse_cron_field(parts[1], 0, 23)
        doms = _parse_cron_field(parts[2], 1, 31)
        months = _parse_cron_field(parts[3], 1, 12)
        dows = _parse_cron_field(parts[4], 0, 6, is_dow=True)
    except ValueError:
        return False

    cron_dow = (dt.weekday() + 1) % 7
    return (
        dt.minute in minutes
        and dt.hour in hours
        and dt.day in doms
        and dt.month in months
        and cron_dow in dows
    )


def extract_page_blocks(text: str) -> list[tuple[str, str]]:
    """Extract (title, content_md) tuples from :::page{title="..."} ... ::: blocks."""
    pages: list[tuple[str, str]] = []
    for match in _PAGE_BLOCK_RE.finditer(text):
        title = (match.group(1) or match.group(2) or "").strip()
        body = (match.group(3) or "").strip()
        if title:
            pages.append((title, body))
    return pages


_SHELL_TOOL_SUBSTRINGS: tuple[str, ...] = (
    "command",
    "shell",
    "term",
    "pty",
    "bash",
    "exec",
    "subprocess",
    "spawn_process",
    "run_cmd",
    "eval_tool",
)
_SHELL_TOOL_TOKENS: frozenset[str] = frozenset(
    {
        "sh",
        "zsh",
        "dash",
        "ksh",
        "ash",
        "csh",
        "tcsh",
        "fish",
        "cmd",
        "process",
        "python",
        "python2",
        "python3",
        "eval",
        "script",
    }
)


_EVENT_COMMAND_KEYS: tuple[str, ...] = (
    "command",
    "cmd",
    "command_line",
    "cmdline",
    "CommandLine",
    "script",
    "code",
    "shell",
    "bash",
    "argv",
)
_EVENT_COMMAND_KEYS_LOWER: tuple[str, ...] = tuple(
    dict.fromkeys(k.lower() for k in _EVENT_COMMAND_KEYS)
)
_EVENT_NESTED_COMMAND_CONTAINER_KEYS_LOWER: tuple[str, ...] = (
    "args",
    "arguments",
    "parameters",
    "tool_params",
    "input",
    "tool_info",
    "payload",
    "data",
)
_EVENT_LIST_COMMAND_CONTAINER_KEYS_LOWER: frozenset[str] = frozenset(
    {"args", "arguments", "input", "payload", "data"}
)


def _decode_event_mapping(raw: Any) -> Mapping[str, Any] | None:
    if isinstance(raw, Mapping):
        return raw or None
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            with contextlib.suppress(json.JSONDecodeError, ValueError):
                decoded = json.loads(stripped)
                if isinstance(decoded, Mapping) and decoded:
                    return decoded
    return None


def _normalize_event_command_values(raw: Any, *, _depth: int = 0) -> list[str]:
    if raw is None or isinstance(raw, bool) or _depth > 4:
        return []
    if isinstance(raw, Mapping):
        return _extract_event_command_strs(raw, _depth=_depth + 1)
    if isinstance(raw, (list, tuple)):
        if raw and all(isinstance(x, Mapping) for x in raw):
            out_m: list[str] = []
            seen_m: set[str] = set()
            for x in raw:
                for found_m in _extract_event_command_strs(x, _depth=_depth + 1):
                    if found_m not in seen_m:
                        seen_m.add(found_m)
                        out_m.append(found_m)
            return out_m
        parts = [str(x) for x in raw if x is not None]
        if not parts or not any(p.strip() for p in parts):
            return []
        joined = shlex.join(parts).strip()
        return [joined] if joined else []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        if len(text) >= 2 and (
            (text[0] == '"' and text[-1] == '"')
            or (text[0] == "[" and text[-1] == "]")
            or (text[0] == "{" and text[-1] == "}")
        ):
            with contextlib.suppress(json.JSONDecodeError, ValueError):
                decoded = json.loads(text)
                if isinstance(decoded, (str, list, tuple, Mapping)):
                    nested = _normalize_event_command_values(decoded, _depth=_depth + 1)
                    if nested:
                        return nested
        return [text]
    return []


def _normalize_event_command_value(raw: Any, *, _depth: int = 0) -> str | None:
    vals = _normalize_event_command_values(raw, _depth=_depth)
    return vals[0] if vals else None


def _extract_event_list_commands(raw: Any, *, _depth: int = 0) -> list[str]:
    if isinstance(raw, (list, tuple)):
        return _normalize_event_command_values(raw, _depth=_depth)
    if isinstance(raw, str):
        stripped = raw.strip()
        if len(stripped) >= 2 and stripped[0] == "[" and stripped[-1] == "]":
            with contextlib.suppress(json.JSONDecodeError, ValueError):
                decoded = json.loads(stripped)
                if isinstance(decoded, list):
                    return _normalize_event_command_values(decoded, _depth=_depth)
    return []


def _extract_event_list_command(raw: Any, *, _depth: int = 0) -> str | None:
    vals = _extract_event_list_commands(raw, _depth=_depth)
    return vals[0] if vals else None


def _extract_event_command_strs(ev: Mapping[str, Any], *, _depth: int = 0) -> list[str]:
    if _depth > 4:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def _add_vals(vals: list[str]) -> None:
        for item in vals:
            if item not in seen:
                seen.add(item)
                found.append(item)

    raw_cmds = ev.get("commands")
    if isinstance(raw_cmds, (list, tuple)):
        for elem in raw_cmds:
            _add_vals(_normalize_event_command_values(elem, _depth=_depth + 1))

    for k in _EVENT_COMMAND_KEYS:
        if k in ev and ev[k] is not None:
            _add_vals(_normalize_event_command_values(ev[k], _depth=_depth + 1))
    for low_k in _EVENT_COMMAND_KEYS_LOWER:
        for k, v in ev.items():
            if v is not None and str(k).lower() == low_k:
                _add_vals(_normalize_event_command_values(v, _depth=_depth + 1))
    for container_low in _EVENT_NESTED_COMMAND_CONTAINER_KEYS_LOWER:
        for k, v in ev.items():
            if v is not None and str(k).lower() == container_low:
                nested = _decode_event_mapping(v)
                if nested is not None:
                    _add_vals(_extract_event_command_strs(nested, _depth=_depth + 1))
                elif container_low in _EVENT_LIST_COMMAND_CONTAINER_KEYS_LOWER:
                    _add_vals(_extract_event_list_commands(v, _depth=_depth + 1))
    return found


def _extract_event_command_str(ev: Mapping[str, Any], *, _depth: int = 0) -> str | None:
    cmds = _extract_event_command_strs(ev, _depth=_depth)
    return cmds[0] if cmds else None


def _infer_tool_category(tool_name: str, *, command: str | None = None) -> str:
    if isinstance(command, str) and command.strip():
        return "terminal"
    low = tool_name.lower()
    tokens = {tok for tok in re.split(r"[^a-z0-9]+", low) if tok}
    if (
        any(tok in low for tok in _SHELL_TOOL_SUBSTRINGS)
        or bool(tokens & _SHELL_TOOL_TOKENS)
        or any(tok.startswith("python") for tok in tokens)
    ):
        return "terminal"
    if any(
        tok in low for tok in ("browser", "web", "url", "http", "navigate", "click", "playwright")
    ):
        return "browser"
    if any(tok in low for tok in ("file", "read", "write", "edit", "dir", "grep", "find")):
        return "files"
    if any(tok in low for tok in ("search", "query", "scada", "maint")):
        return "search"
    return "agent"


def _is_mcp_tool(tool_name: str) -> bool:
    low = tool_name.strip().lower()
    if not low:
        return False
    if low.startswith("mcp"):
        return True
    return "mcp" in re.split(r"[^a-z0-9]+", low)


def _infer_action_kind(
    tool_name: str,
    category: str,
    *,
    known_read_only_mcp_tools: frozenset[str] = frozenset(),
    command: str | None = None,
) -> str:
    low = tool_name.strip().lower()
    has_command = isinstance(command, str) and bool(command.strip())
    if _is_mcp_tool(low):
        return "read" if (not has_command and low in known_read_only_mcp_tools) else "write"
    if has_command or category == "terminal":
        return "write"
    if low.startswith(("scada.read", "maint.read")) or any(
        tok in low for tok in ("read_", "get_", "list_", "search", "inspect", "view", "extract")
    ):
        return "read"
    if any(
        tok in low
        for tok in (
            "write",
            "edit",
            "delete",
            "remove",
            "exec",
            "run_command",
            "bash",
            "pty",
            "click",
            "type",
            "fill",
        )
    ):
        return "write"
    return "read"


def _close_unbalanced_shell_quotes(text: str) -> str | None:
    """Close an unbalanced single/double quote at EOF when inspecting partial shell text."""
    in_single = False
    in_double = False
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
    if in_single:
        return f"{text}'"
    if in_double:
        return f'{text}"'
    return None


def _find_unquoted_safety_variant(tool_name: str, text: str) -> str | None:
    """Return a quote-normalized variant if it triggers a non-syntax safety_floor violation."""
    candidates: list[str] = []
    closed = _close_unbalanced_shell_quotes(text)
    if closed and closed != text:
        candidates.append(closed)
    spaced = re.sub(r"[\'\"]", " ", text).strip()
    if spaced and spaced != text and spaced not in candidates:
        candidates.append(spaced)
    for variant in candidates:
        err = safety_floor(tool_name, {"command": variant})
        if err is not None and not err.startswith("safety_floor:unparseable_shell_syntax"):
            return variant
    return None


def _normalize_rule_token(word: str) -> str:
    if len(word) >= 5 and word.endswith("ing"):
        cand = word[:-3]
        stem = cand if any(c in "aeiouy" for c in cand) else word
    elif len(word) > 4 and word.endswith(("ies", "ied")):
        stem = f"{word[:-3]}y"
    elif word.endswith("ees") and len(word) >= 4:
        stem = word[:-1]
    elif len(word) >= 4 and word.endswith("ed") and not word.endswith("eed"):
        cand = word[:-2]
        if len(word) == 4 and word[0] not in "aeiouy" and word[1] not in "aeiouy":
            stem = word
        elif len(word) == 4 and cand.endswith("i"):
            stem = word[:-1]
        else:
            stem = cand
    elif len(word) >= 4 and word.endswith("es"):
        stem = word[:-2]
    elif (
        len(word) >= 4
        and word.endswith("s")
        and not word.endswith(("ss", "us", "is", "as", "os"))
    ):
        stem = word[:-1]
    else:
        stem = word
    # Collapse CVC doubled consonants produced by -ing/-ed stripping (e.g. running -> runn -> run)
    if (
        stem != word
        and len(stem) >= 4
        and stem[-1] == stem[-2]
        and stem[-1] in {"b", "d", "g", "m", "n", "p", "r", "t"}
        and stem[-3] in "aeiou"
    ):
        stem = stem[:-1]
    if (
        len(stem) >= 3
        and stem.endswith("e")
        and not stem.endswith(("ee", "ie", "ye", "oe", "ue", "ae"))
    ):
        stem = stem[:-1]
    return stem


def _rule_tokens(text: str, *, include_aux: bool = False) -> set[str]:
    words = [
        w
        for w in re.findall(r"[a-z0-9][a-z0-9_-]*", text.lower())
        if len(w) >= 3 or w in _SHORT_2CHAR_TOKENS
    ]
    primary = {
        _normalize_rule_token(w)
        for w in words
        if w not in _STOP_WORDS and w not in _AUXILIARY_RULE_TOKENS
    }
    if include_aux or len(primary) < 2:
        return {_normalize_rule_token(w) for w in words if w not in _STOP_WORDS}
    return primary


def _match_ask_first_rule(prompt: str, rules: list[dict[str, Any]]) -> str | None:
    prompt_low = prompt.lower()
    prompt_norm = " ".join(prompt_low.split())
    prompt_tokens = _rule_tokens(prompt_low, include_aux=True)
    has_destructive = any(pat.search(prompt) is not None for pat in _DESTRUCTIVE_PATTERNS)

    # Allow rules can explicitly override matching actions
    for rule in rules:
        if rule.get("bucket") != "allow_auto":
            continue
        r_text = str(rule.get("rule_text", "")).strip()
        r_low = r_text.lower()
        if r_low.startswith("allow exact:"):
            exact_target = " ".join(r_low[len("allow exact:") :].strip().split())
            if exact_target and prompt_norm == exact_target:
                return None
            continue
        if r_low.startswith("allow exact-sha256:"):
            expected_hash = r_low[len("allow exact-sha256:") :].strip()
            if (
                expected_hash
                and hashlib.sha256(prompt_norm.encode("utf-8")).hexdigest() == expected_hash
            ):
                return None
            continue
        quoted = [
            m[0] or m[1]
            for m in re.findall(r'"([^"]{3,})"|\'([^\']{3,})\'', r_low)
        ]
        if quoted:
            if any(phrase in prompt_low for phrase in quoted):
                return None
            continue
        r_tokens = _rule_tokens(r_low)
        if r_tokens and len(r_tokens & prompt_tokens) >= max(2, min(3, len(r_tokens))):
            return None

    for rule in rules:
        if rule.get("bucket") != "ask_first":
            continue
        r_text = str(rule.get("rule_text", "")).strip()
        r_low = r_text.lower()
        r_words = set(re.findall(r"[a-z0-9_-]+", r_low))
        if has_destructive and (r_words & _RULE_DESTRUCTIVE_HINTS):
            return r_text
        quoted = [
            m[0] or m[1]
            for m in re.findall(r'"([^"]{3,})"|\'([^\']{3,})\'', r_low)
        ]
        if any(phrase in prompt_low for phrase in quoted):
            return r_text
        r_tokens = _rule_tokens(r_low)
        if len(r_tokens) >= 2 and len(r_tokens & prompt_tokens) >= 2:
            return r_text
    return None


def _slug_variants(name: str) -> set[str]:
    low = name.strip().lower()
    if not low:
        return set()
    slug_hyphen = re.sub(r"[^a-z0-9]+", "-", low).strip("-")
    slug_underscore = re.sub(r"[^a-z0-9]+", "_", low).strip("_")
    space_underscore = low.replace(" ", "_")
    space_hyphen = low.replace(" ", "-")
    compact = re.sub(r"[^a-z0-9]+", "", low)
    return {
        v for v in (low, slug_hyphen, slug_underscore, space_underscore, space_hyphen, compact) if v
    }


def _extract_page_context_id(
    user_message: dict[str, Any],
    explicit_page_context_id: str | None = None,
) -> str | None:
    if explicit_page_context_id and str(explicit_page_context_id).strip():
        return str(explicit_page_context_id).strip()
    direct = user_message.get("page_context_id")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    meta = user_message.get("metadata")
    if isinstance(meta, dict):
        m_val = meta.get("page_context_id")
        if isinstance(m_val, str) and m_val.strip():
            return m_val.strip()
    meta_json = user_message.get("metadata_json")
    if isinstance(meta_json, str) and meta_json.strip():
        with contextlib.suppress(ValueError, TypeError):
            parsed = json.loads(meta_json)
            if isinstance(parsed, dict) and isinstance(parsed.get("page_context_id"), str):
                val = str(parsed["page_context_id"]).strip()
                if val:
                    return val
    return None


_RAW_RUNTIME_ERROR_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|net::ERR_[A-Z_]+|\[Errno\s+\d+\]|"
    r"Playwright error|SourceUnavailableError|All requested industrial sources failed|"
    r"connection refused|ECONNREFUSED|https?://|"
    r'"available_sources"\s*:\s*\[|"missing_sources"\s*:\s*\[|'
    r"\b(?:OSError|RuntimeError|ValueError|TypeError|KeyError|AttributeError|"
    r"ImportError|ConnectionError|TimeoutError|FileNotFoundError|PermissionError|"
    r"sqlite3\.\w*Error)\s*:)",
    re.IGNORECASE,
)
_ACTIONABLE_GUIDANCE_RE = re.compile(
    r"(?i)\b(?:retry|reconnect|reload|try\s+again|switch\s+(?:to|engine|backend|mode|model)|"
    r"please\s+(?:check|verify|select|enable|configure|install|start|open)|"
    r"(?:check|verify)\s+(?:your|the|that|settings|network|connection)|"
    r"(?:install|configure|enable)\s+(?:the|a|an|your|[a-z0-9_-]{2,}))\b"
)


def _format_runtime_error_message(
    raw_answer: str,
    partial_info: Mapping[str, Any] | None = None,
) -> str:
    """Sanitize raw runtime/transport failures into actionable, secret-free guidance."""
    cleaned_raw = str(scrub_v1_payload(raw_answer or "")).strip()
    source_names: list[str] = []
    if isinstance(partial_info, Mapping):
        raw_sources: list[str] = []
        missing = partial_info.get("missing_sources")
        if isinstance(missing, (list, tuple)):
            raw_sources.extend(str(s) for s in missing if str(s).strip())
        src_errs = partial_info.get("source_errors")
        if isinstance(src_errs, Mapping):
            raw_sources.extend(str(k) for k in src_errs if str(k).strip())
        seen_src: set[str] = set()
        for src in raw_sources:
            base = src.split(":", 1)[0].strip().lower()
            label = (
                "SCADA"
                if base == "scada"
                else ("Maintenance" if base in {"maintenance", "maint"} else src.strip())
            )
            if label and label not in seen_src:
                seen_src.add(label)
                source_names.append(label)

    if not cleaned_raw or _RAW_RUNTIME_ERROR_RE.search(cleaned_raw):
        low = cleaned_raw.lower()
        if source_names:
            lead = f"Unable to reach the configured industrial sources ({', '.join(source_names)})."
        elif (
            "connection refused" in low
            or "err_connection_refused" in low
            or "econnrefused" in low
        ):
            lead = "Unable to connect to the configured service endpoint (connection refused)."
        elif "timeout" in low or "timed out" in low:
            lead = "The runtime request timed out before receiving a response."
        else:
            lead = "The runtime task could not be completed due to a service or execution error."
        return (
            f"{lead} Please check that the required services are running and reachable, "
            "verify your facility or engine settings, and try again."
        )

    if not _ACTIONABLE_GUIDANCE_RE.search(cleaned_raw):
        return (
            f"{cleaned_raw.rstrip('.')}."
            " Please check your service or facility configuration and try again."
        )
    return cleaned_raw


def _format_partial_info_summary(partial_info: Any) -> list[str]:
    """Format partial_info into human-readable lines without raw JSON/stack dumps."""
    items: list[str] = []
    if not partial_info:
        return items
    if not isinstance(partial_info, Mapping):
        scrubbed = str(scrub_v1_payload(partial_info)).strip()
        if scrubbed and not _RAW_RUNTIME_ERROR_RE.search(scrubbed):
            items.append(scrubbed)
        return items

    avail = partial_info.get("available_sources")
    if isinstance(avail, (list, tuple)) and avail:
        items.append("Available sources: " + ", ".join(str(s) for s in avail))

    missing = partial_info.get("missing_sources")
    if isinstance(missing, (list, tuple)) and missing:
        items.append("Unavailable sources: " + ", ".join(str(s) for s in missing))

    rejected_ids = partial_info.get("rejected_record_ids")
    if isinstance(rejected_ids, (list, tuple)) and rejected_ids:
        items.append(
            "Excluded stale/invalid records: " + ", ".join(str(rid) for rid in rejected_ids)
        )

    auth_exp = partial_info.get("auth_expired_sources")
    if isinstance(auth_exp, (list, tuple)) and auth_exp:
        items.append("Authentication expired for: " + ", ".join(str(s) for s in auth_exp))

    unknown_steps = partial_info.get("unknown_step_ids")
    if isinstance(unknown_steps, (list, tuple)) and unknown_steps:
        items.append("Unresolved steps: " + ", ".join(str(s) for s in unknown_steps))

    reason_val = partial_info.get("reason")
    if reason_val and not items:
        items.append(f"Detail: {scrub_v1_payload(str(reason_val))}")
    return items


class AgentTurnRunner:
    """Manages async bot turns, multi-bot handoffs, HITL approval resumes, and routines."""

    def __init__(
        self,
        *,
        store: WorkspaceStore,
        event_bus: EventBus,
        live_browser: LiveBrowserController,
        coordinator: CoordinatorProtocol,
        uploads_dir: Path,
        memory_store: Any | None = None,
        policy_gateway: PolicyGateway | None = None,
        router: LaneRouter | None = None,
        airlock: EvidenceAirlock | None = None,
        computer_gateway: Any | None = None,
        smtp_config: dict[str, Any] | None = None,
        facility_config: FacilityConfig | None = None,
        known_read_only_mcp_tools: Iterable[str] | None = None,
        webhook_secrets: Mapping[str, str] | None = None,
        allow_loopback_webhooks: bool = False,
    ) -> None:
        self._store = store
        self._event_bus = event_bus
        self._live_browser = live_browser
        self._coordinator = coordinator
        self._uploads_dir = uploads_dir
        self._memory_store = memory_store
        self._computer_gateway = computer_gateway
        self._smtp_config = dict(smtp_config) if smtp_config is not None else None
        self._facility_config = facility_config
        self._allow_loopback_webhooks = bool(allow_loopback_webhooks)
        self._known_read_only_mcp_tools: frozenset[str] = frozenset(
            str(t).strip().lower() for t in (known_read_only_mcp_tools or ()) if str(t).strip()
        )
        self._webhook_secrets: dict[str, str] = {
            str(k).strip(): str(v).strip()
            for k, v in (webhook_secrets or {}).items()
            if str(k).strip() and str(v).strip() and str(v).strip() != "[REDACTED]"
        }

        self.policy_audit_log: list[dict[str, Any]] = []
        self.airlock_audit_log: list[dict[str, Any]] = []

        self._policy_gateway = policy_gateway or PolicyGateway(
            default_studio_policy_set(allow_general_writes=True),
            audit_sink=self._record_policy_audit,
            require_audit_sink=True,
        )
        self._router = router or LaneRouter()
        self._airlock = airlock or EvidenceAirlock(audit_sink=self._record_airlock_audit)

        self._active_tasks: dict[str, asyncio.Task[None]] = {}
        self._active_turns: dict[str, str] = {}
        self._active_runtime_runs: dict[str, str] = {}
        self._active_routine_runs: dict[str, tuple[str | None, str]] = {}
        self._thread_locks: dict[str, asyncio.Lock] = {}
        self._routine_tasks: set[asyncio.Task[None]] = set()
        self._routine_tasks_by_routine: dict[str, set[asyncio.Task[None]]] = {}
        self._routine_coord_runs: dict[str, set[str]] = {}
        self._thread_routine_tasks: dict[str, dict[tuple[str, str], asyncio.Task[None]]] = {}
        self._scheduler_task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self._stopping = False
        self._last_cron_minute: dict[str, str] = {}

    def _record_policy_audit(self, event: dict[str, Any]) -> str:
        scrubbed = scrub_v1_payload(event)
        if isinstance(scrubbed, dict):
            self.policy_audit_log.append(scrubbed)
            if len(self.policy_audit_log) > 500:
                del self.policy_audit_log[: len(self.policy_audit_log) - 500]
        return f"pol_{uuid.uuid4().hex[:10]}"

    def _record_airlock_audit(self, event: dict[str, Any]) -> str:
        scrubbed = scrub_v1_payload(event)
        if isinstance(scrubbed, dict):
            self.airlock_audit_log.append(scrubbed)
            if len(self.airlock_audit_log) > 500:
                del self.airlock_audit_log[: len(self.airlock_audit_log) - 500]
        return str(event.get("audit_id") or f"air_{uuid.uuid4().hex[:10]}")

    def _get_thread_lock(self, thread_id: str) -> asyncio.Lock:
        lock = self._thread_locks.get(thread_id)
        if lock is None:
            lock = asyncio.Lock()
            self._thread_locks[thread_id] = lock
        return lock

    def _is_app_enabled(self, app_id: str) -> bool:
        try:
            apps = self._store.list_connected_apps()
        except Exception:  # noqa: BLE001
            return True
        for app in apps:
            if str(app.get("id")) == app_id:
                return bool(app.get("enabled", True))
        return True

    def _get_connected_app(self, app_id: str) -> dict[str, Any] | None:
        try:
            for app in self._store.list_connected_apps():
                if str(app.get("id")) == app_id:
                    return app
        except Exception:  # noqa: BLE001
            return None
        return None

    def _resolve_facility_config(self) -> FacilityConfig | None:
        if self._facility_config is not None:
            return self._facility_config
        coord_cfg = getattr(self._coordinator, "_facility_config", None)
        return coord_cfg if isinstance(coord_cfg, FacilityConfig) else None

    def _resolve_runtime_scope(
        self,
        *,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
        user_message: Mapping[str, Any] | None = None,
        allowed_tools: tuple[str, ...] = (),
    ) -> TaskScope:
        meta = user_message.get("metadata") if isinstance(user_message, Mapping) else None
        meta_map = meta if isinstance(meta, Mapping) else {}

        raw_fac: Any = facility_id
        if raw_fac is None and isinstance(user_message, Mapping):
            raw_fac = user_message.get("facility_id")
        if raw_fac is None:
            raw_fac = meta_map.get("facility_id")
        if raw_fac is None:
            cfg = self._resolve_facility_config()
            if cfg is not None and cfg.facility_id:
                raw_fac = cfg.facility_id
        if raw_fac is None:
            env_fac = os.environ.get("GROKBOT_FACILITY_ID", "").strip()
            if env_fac:
                raw_fac = env_fac
        if raw_fac is None:
            raw_fac = "facility-a"

        resolved_fac = str(raw_fac).strip()
        if not resolved_fac:
            raise ValueError("facility_id must not be empty.")
        if contains_sensitive_scope_secret(resolved_fac):
            raise ValueError("facility_id must not contain sensitive credentials.")

        raw_areas: Sequence[str] | None = allowed_areas
        if not raw_areas and isinstance(user_message, Mapping):
            msg_areas = user_message.get("allowed_areas")
            if isinstance(msg_areas, (list, tuple)):
                raw_areas = [str(a) for a in msg_areas]
        if not raw_areas:
            meta_areas = meta_map.get("allowed_areas")
            if isinstance(meta_areas, (list, tuple)):
                raw_areas = [str(a) for a in meta_areas]

        cleaned_areas: list[str] = []
        seen_areas: set[str] = set()
        for raw_area in raw_areas or ():
            area = str(raw_area).strip()
            if not area:
                continue
            if contains_sensitive_scope_secret(area):
                raise ValueError("allowed_areas must not contain sensitive credentials.")
            if area not in seen_areas:
                seen_areas.add(area)
                cleaned_areas.append(area)

        return TaskScope(
            facility_id=resolved_fac,
            allowed_areas=tuple(cleaned_areas),
            allowed_tools=allowed_tools,
            read_only=True,
        )

    @property
    def active_turns_count(self) -> int:
        return sum(1 for task in self._active_tasks.values() if not task.done())

    # ------------------------------------------------------------------
    # Lifecycle & Background Scheduler
    # ------------------------------------------------------------------

    async def start_scheduler(self) -> None:
        """Start the lightweight background cron & approval-expiration loop."""
        if self._scheduler_task is not None and not self._scheduler_task.done():
            return
        self._stopping = False
        self._stop_event = asyncio.Event()
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())

    async def stop_scheduler(self) -> None:
        """Stop scheduler loop and cancel any in-flight turn/routine tasks cleanly."""
        self._stopping = True
        if self._stop_event is not None:
            self._stop_event.set()
        if self._scheduler_task is not None:
            self._scheduler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._scheduler_task
            self._scheduler_task = None

        all_tasks = list(self._active_tasks.values()) + list(self._routine_tasks)
        for task in all_tasks:
            if not task.done():
                task.cancel()
        for task in all_tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._active_tasks.clear()
        self._active_turns.clear()
        self._active_runtime_runs.clear()
        self._active_routine_runs.clear()
        self._routine_tasks.clear()
        self._routine_tasks_by_routine.clear()
        self._routine_coord_runs.clear()
        self._thread_routine_tasks.clear()

    async def _scheduler_loop(self) -> None:
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            try:
                await self._scheduler_tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Scheduler tick error")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=30.0)
            except TimeoutError:
                continue

    async def _scheduler_tick(self) -> None:
        expired = self._store.expire_stale_approvals()
        for appr in expired:
            self._event_bus.publish(
                "hitl.approval.expired",
                {"approval": appr},
                bot_id=str(appr["bot_id"]),
                thread_id=str(appr["thread_id"]),
            )
            self._sync_bot_attention(str(appr["bot_id"]))

        now_utc = datetime.now(tz=UTC)
        routines = self._store.list_routines(enabled_only=True)
        for rtn in routines:
            if rtn.get("schedule_type") != "cron":
                continue
            tz_name = str(rtn.get("timezone") or "UTC")
            tz: ZoneInfo | Any
            try:
                tz = ZoneInfo(tz_name)
            except (ZoneInfoNotFoundError, KeyError):
                tz = UTC
            local_dt = now_utc.astimezone(tz)
            minute_key = local_dt.strftime("%Y-%m-%dT%H:%M")
            rtn_id = str(rtn["id"])
            if self._last_cron_minute.get(rtn_id) == minute_key:
                continue
            if cron_matches(rtn.get("cron_expr"), local_dt):
                self._last_cron_minute[rtn_id] = minute_key
                with contextlib.suppress(Exception):
                    await self.execute_routine(rtn_id, trigger="cron")

    # ------------------------------------------------------------------
    # Presence & Turn Management
    # ------------------------------------------------------------------

    def _emit_presence(
        self,
        bot_id: str,
        *,
        state: str,
        subtext: str,
        computer_active: bool = False,
        step_label: str | None = None,
        thread_id: str | None = None,
        turn_id: str | None = None,
        needs_attention: bool | None = None,
    ) -> None:
        updates: dict[str, Any] = {
            "status_state": state,
            "status_subtext": subtext[:240],
            "computer_active": computer_active,
        }
        if needs_attention is not None:
            updates["needs_attention"] = needs_attention
        with contextlib.suppress(StoreNotFoundError):
            self._store.update_bot(bot_id, updates)

        payload: dict[str, Any] = {
            "state": state,
            "subtext": subtext[:240],
            "computer_active": computer_active,
        }
        if step_label:
            payload["step_label"] = step_label[:120]
        self._event_bus.publish(
            "bot.presence",
            payload,
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )

    def _sync_bot_attention(self, bot_id: str) -> None:
        bot = self._store.get_bot(bot_id)
        if bot is None:
            return
        pending = self._store.count_pending_approvals_for_bot(bot_id)
        if pending == 0 and bot["needs_attention"]:
            next_state = "idle" if bot["status_state"] == "waiting_human" else bot["status_state"]
            subtext = "Nothing is blocked" if next_state == "idle" else str(bot["status_subtext"])
            self._emit_presence(
                bot_id,
                state=str(next_state),
                subtext=subtext,
                computer_active=bool(bot["computer_active"]),
                thread_id=str(bot["thread_id"]),
                needs_attention=False,
            )

    def _reset_routine_presence_idle(
        self,
        bot_id: str,
        thread_id: str,
        *,
        subtext: str = "Idle",
    ) -> None:
        if self._store.count_pending_approvals_for_bot(bot_id) == 0:
            self._emit_presence(
                bot_id,
                state="idle",
                subtext=subtext,
                computer_active=False,
                thread_id=thread_id,
                needs_attention=False,
            )
        else:
            self._sync_bot_attention(bot_id)

    def start_turn(
        self,
        *,
        thread_id: str,
        user_message: dict[str, Any],
        include_browser_context: bool | None = None,
        model_id: str | None = None,
        thinking_level: str | None = None,
        skill_ids: list[str] | None = None,
        skip_auto_review: bool = False,
        page_context_id: str | None = None,
        ui_lane: Lane | None = None,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> str:
        """Schedule turn synchronously; serialize per-thread after cancelling prior task."""
        prev_task = self._active_tasks.get(thread_id)
        if prev_task is not None and not prev_task.done():
            prev_task.cancel()
        extra_routine_tasks: list[asyncio.Task[None]] = []
        popped_routines = self._thread_routine_tasks.pop(thread_id, {})
        for (r_id, rr_id), r_task in popped_routines.items():
            if not r_task.done():
                r_task.cancel()
                if r_task is not prev_task:
                    extra_routine_tasks.append(r_task)
            self._fail_interrupted_routine_run(
                r_id,
                rr_id,
                thread_id=thread_id,
                error="Routine superseded by new turn.",
            )
        prev_routine_ref = self._active_routine_runs.pop(thread_id, None)
        if prev_routine_ref is not None:
            self._fail_interrupted_routine_run(
                prev_routine_ref[0],
                prev_routine_ref[1],
                thread_id=thread_id,
                error="Runtime resume superseded by new turn.",
            )

        turn_id = f"trn_{uuid.uuid4().hex[:12]}"
        self._active_turns[thread_id] = turn_id

        resolved_page_ctx = _extract_page_context_id(user_message, page_context_id)

        task = asyncio.create_task(
            self._run_thread_turn_serialized(
                previous_task=prev_task,
                extra_previous_tasks=tuple(extra_routine_tasks),
                thread_id=thread_id,
                turn_id=turn_id,
                user_message=user_message,
                include_browser_context=include_browser_context,
                model_id=model_id,
                thinking_level=thinking_level,
                skill_ids=skill_ids or [],
                skip_auto_review=skip_auto_review,
                page_context_id=resolved_page_ctx,
                ui_lane=ui_lane,
                facility_id=facility_id,
                allowed_areas=tuple(allowed_areas) if allowed_areas else None,
            )
        )
        self._active_tasks[thread_id] = task

        def _cleanup(done_task: asyncio.Task[None]) -> None:
            if self._active_tasks.get(thread_id) is done_task:
                self._active_tasks.pop(thread_id, None)
            if self._active_turns.get(thread_id) == turn_id:
                self._active_turns.pop(thread_id, None)

        task.add_done_callback(_cleanup)
        return turn_id

    async def _run_thread_turn_serialized(
        self,
        *,
        previous_task: asyncio.Task[None] | None,
        extra_previous_tasks: tuple[asyncio.Task[None], ...] = (),
        thread_id: str,
        turn_id: str,
        user_message: dict[str, Any],
        include_browser_context: bool | None,
        model_id: str | None,
        thinking_level: str | None,
        skill_ids: list[str],
        skip_auto_review: bool,
        page_context_id: str | None,
        ui_lane: Lane | None,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> None:
        if previous_task is not None and not previous_task.done():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await previous_task
        for extra_task in extra_previous_tasks:
            if not extra_task.done():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await extra_task

        async with self._get_thread_lock(thread_id):
            if self._active_turns.get(thread_id) != turn_id:
                return
            await self._run_thread_turn(
                thread_id=thread_id,
                turn_id=turn_id,
                user_message=user_message,
                include_browser_context=include_browser_context,
                model_id=model_id,
                thinking_level=thinking_level,
                skill_ids=skill_ids,
                skip_auto_review=skip_auto_review,
                page_context_id=page_context_id,
                ui_lane=ui_lane,
                facility_id=facility_id,
                allowed_areas=allowed_areas,
            )

    async def wait_for_active_turn(self, thread_id: str) -> None:
        """Await any currently tracked background turn/resume task for thread_id."""
        task = self._active_tasks.get(thread_id)
        if task is not None and not task.done():
            await task
        extra_tasks = list(self._thread_routine_tasks.get(thread_id, {}).values())
        for extra_task in extra_tasks:
            if not extra_task.done():
                await extra_task

    def _fail_interrupted_routine_run(
        self,
        routine_id: str | None,
        routine_run_id: str,
        *,
        thread_id: str,
        error: str,
    ) -> bool:
        existing_rtn_run = self._store.get_routine_run(routine_run_id)
        if existing_rtn_run is None or existing_rtn_run.get("status") not in {
            "waiting_approval",
            "running",
            "queued",
        }:
            return False
        finished_at = utc_iso_now()
        eff_routine_id = routine_id or str(existing_rtn_run.get("routine_id") or "")
        if eff_routine_id:
            if self._store.get_routine(eff_routine_id) is None:
                return False
            with contextlib.suppress(StoreNotFoundError):
                self._store.update_routine(eff_routine_id, {"last_run_at": finished_at})
        with contextlib.suppress(StoreNotFoundError):
            failed_rtn = self._store.update_routine_run(
                routine_run_id,
                {
                    "status": "failed",
                    "error": error,
                    "finished_at": finished_at,
                },
            )
            self._event_bus.publish(
                "routine.run.status",
                {"routine_id": eff_routine_id, "run": failed_rtn},
                bot_id=str(existing_rtn_run.get("bot_id") or ""),
                thread_id=thread_id,
            )
            return True
        return False

    async def cancel_routine(self, routine_id: str) -> None:
        """Cancel any active tasks and runtime runs for routine_id and await settlement."""
        tasks_to_cancel: list[asyncio.Task[None]] = []
        seen_tasks: set[int] = set()

        def _collect(task: asyncio.Task[None] | None) -> None:
            if task is not None and id(task) not in seen_tasks:
                seen_tasks.add(id(task))
                tasks_to_cancel.append(task)

        for t in self._routine_tasks_by_routine.pop(routine_id, set()):
            _collect(t)

        affected_threads: set[str] = set()
        for thread_id, rtn_map in list(self._thread_routine_tasks.items()):
            for key in list(rtn_map):
                if key[0] == routine_id:
                    affected_threads.add(thread_id)
                    _collect(rtn_map.pop(key, None))
            if not rtn_map:
                self._thread_routine_tasks.pop(thread_id, None)

        for thread_id, ref in list(self._active_routine_runs.items()):
            if ref[0] == routine_id:
                affected_threads.add(thread_id)
                self._active_routine_runs.pop(thread_id, None)

        for thread_id in affected_threads:
            active_turn = self._active_turns.get(thread_id) or ""
            active_task = self._active_tasks.get(thread_id)
            if active_turn.startswith("rtn_") or (
                active_task is not None and id(active_task) in seen_tasks
            ):
                _collect(self._active_tasks.pop(thread_id, None))
                self._active_turns.pop(thread_id, None)
                self._active_runtime_runs.pop(thread_id, None)

        for t in tasks_to_cancel:
            if not t.done():
                t.cancel()

        for t in tasks_to_cancel:
            if not t.done():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t

        remaining_coord_runs = self._routine_coord_runs.pop(routine_id, set())
        for coord_run_id in remaining_coord_runs:
            try:
                await maybe_await(
                    self._coordinator.cancel_task(coord_run_id, reason="routine_deleted")
                )
            except (KeyError, InvalidStateTransitionError):
                pass
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Failed cancelling runtime run %s for deleted routine %s",
                    coord_run_id,
                    routine_id,
                )

    async def interrupt(self, thread_id: str) -> bool:
        """Cancel any active turn for thread_id, mark streaming messages interrupted, reset bots."""
        task = self._active_tasks.pop(thread_id, None)
        turn_id = self._active_turns.pop(thread_id, None)
        run_id = self._active_runtime_runs.pop(thread_id, None)
        routine_ref = self._active_routine_runs.pop(thread_id, None)
        popped_routines = self._thread_routine_tasks.pop(thread_id, {})
        was_running = False
        tasks_to_await: list[asyncio.Task[None]] = []
        if task is not None and not task.done():
            was_running = True
            task.cancel()
            tasks_to_await.append(task)
        for r_task in popped_routines.values():
            if not r_task.done():
                was_running = True
                r_task.cancel()
                if r_task is not task:
                    tasks_to_await.append(r_task)
        if run_id:
            try:
                await maybe_await(
                    self._coordinator.cancel_task(run_id, reason="interrupted_by_operator")
                )
                was_running = True
            except (KeyError, InvalidStateTransitionError):
                pass
            except Exception:  # noqa: BLE001
                logger.exception("Failed cancelling runtime run %s on interrupt", run_id)
        for t in tasks_to_await:
            if not t.done():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
        if routine_ref is not None and self._fail_interrupted_routine_run(
            routine_ref[0],
            routine_ref[1],
            thread_id=thread_id,
            error="Interrupted by operator.",
        ):
            was_running = True
        for r_id, rr_id in popped_routines:
            if self._fail_interrupted_routine_run(
                r_id,
                rr_id,
                thread_id=thread_id,
                error="Interrupted by operator.",
            ):
                was_running = True

        interrupted_msgs = self._store.mark_streaming_interrupted(thread_id)
        for msg in interrupted_msgs:
            self._event_bus.publish(
                "message.completed",
                {"message_id": msg["id"], "message": msg},
                bot_id=msg.get("sender_bot_id"),
                thread_id=thread_id,
                turn_id=turn_id,
            )

        bot = self._store.get_bot_by_thread(thread_id)
        if bot is not None:
            self._emit_presence(
                str(bot["id"]),
                state="idle",
                subtext="Interrupted by operator",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
        else:
            channel = self._store.get_channel_by_thread(thread_id)
            if channel is not None:
                for bid in channel["bot_ids"]:
                    self._emit_presence(
                        str(bid),
                        state="idle",
                        subtext="Interrupted by operator",
                        computer_active=False,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
        return was_running or bool(interrupted_msgs)

    async def on_approval_resolved(
        self,
        approval: dict[str, Any],
        *,
        decision: str,
        rule_text: str | None = None,
    ) -> None:
        """Handle resolving an approval card (always_allow + resume agy OR runtime run)."""
        bot_id = str(approval["bot_id"])
        thread_id = str(approval["thread_id"])
        raw_args = approval.get("arguments")
        args_dict: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
        pending_ctx = self._store.get_approval_pending_context(str(approval["id"]))
        if decision == "always_allow":
            explicit_rule = (rule_text or "").strip()
            if explicit_rule:
                label = explicit_rule
            else:
                matched_rule = str(args_dict.get("matched_rule") or "").strip()
                args_prompt = str(args_dict.get("prompt") or "").strip()
                ctx_prompt = ""
                if isinstance(pending_ctx, dict):
                    if isinstance(pending_ctx.get("prompt"), str):
                        ctx_prompt = str(pending_ctx["prompt"]).strip()
                    elif isinstance(pending_ctx.get("user_message"), dict):
                        ctx_prompt = str(
                            pending_ctx["user_message"].get("content") or ""
                        ).strip()
                prompt_arg = ctx_prompt if len(ctx_prompt) >= len(args_prompt) else args_prompt
                if matched_rule:
                    if prompt_arg:
                        normalized_prompt = " ".join(prompt_arg.split())
                        exact_limit = MAX_AUTO_REVIEW_RULE_LEN - len(_EXACT_RULE_PREFIX)
                        if len(normalized_prompt) <= exact_limit:
                            label = f"{_EXACT_RULE_PREFIX}{normalized_prompt}"
                        else:
                            digest = hashlib.sha256(
                                normalized_prompt.lower().encode("utf-8")
                            ).hexdigest()
                            label = f"{_EXACT_SHA_PREFIX}{digest}"
                    else:
                        label = f"Allow: {matched_rule}"
                else:
                    label = f"Allow: {approval['title']}".strip()
            self._store.add_auto_review_rule("allow_auto", label)

        self._sync_bot_attention(bot_id)
        run_id_raw = args_dict.get("run_id") or (
            pending_ctx.get("run_id") if isinstance(pending_ctx, dict) else None
        )

        if decision in {"allow_once", "always_allow"}:
            if pending_ctx and isinstance(pending_ctx.get("user_message"), dict):
                self.start_turn(
                    thread_id=str(pending_ctx.get("thread_id") or thread_id),
                    user_message=dict(pending_ctx["user_message"]),
                    include_browser_context=pending_ctx.get("include_browser_context"),
                    model_id=pending_ctx.get("model_id"),
                    thinking_level=pending_ctx.get("thinking_level"),
                    skill_ids=list(pending_ctx.get("skill_ids") or []),
                    skip_auto_review=True,
                    page_context_id=pending_ctx.get("page_context_id"),
                    facility_id=pending_ctx.get("facility_id"),
                    allowed_areas=pending_ctx.get("allowed_areas"),
                )
            elif run_id_raw:
                self._start_runtime_resume(
                    approval=approval,
                    run_id=str(run_id_raw),
                    decision=decision,
                    pending_ctx=pending_ctx if isinstance(pending_ctx, dict) else {},
                )
            elif pending_ctx and isinstance(pending_ctx.get("routine_id"), str):
                routine_id = str(pending_ctx["routine_id"])
                routine_run_id = str(pending_ctx.get("routine_run_id") or "")
                trigger = str(pending_ctx.get("trigger") or "manual")
                routine = self._store.get_routine(routine_id)
                if routine is None:
                    if routine_run_id:
                        with contextlib.suppress(StoreNotFoundError):
                            failed_run = self._store.update_routine_run(
                                routine_run_id,
                                {
                                    "status": "failed",
                                    "error": f"Routine {routine_id} no longer exists.",
                                    "finished_at": utc_iso_now(),
                                },
                            )
                            self._event_bus.publish(
                                "routine.run.status",
                                {"routine_id": routine_id, "run": failed_run},
                                bot_id=bot_id,
                                thread_id=thread_id,
                            )
                    bot = self._store.get_bot(bot_id)
                    bot_name = str(bot["name"]) if bot is not None else "Bot"
                    err_msg = self._store.create_message(
                        thread_id=thread_id,
                        sender_type="bot",
                        sender_bot_id=bot_id,
                        sender_name=bot_name,
                        content=(
                            f"Could not resume routine `{routine_id}`: "
                            "routine no longer exists."
                        ),
                        status="error",
                    )
                    self._event_bus.publish(
                        "message.completed",
                        {"message_id": err_msg["id"], "message": err_msg},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
                else:
                    run_obj: dict[str, Any] | None = None
                    if routine_run_id:
                        with contextlib.suppress(StoreNotFoundError):
                            run_obj = self._store.update_routine_run(
                                routine_run_id,
                                {"status": "running", "error": None},
                            )
                    if run_obj is None:
                        run_obj = self._store.create_routine_run(
                            routine_id, bot_id, trigger=trigger
                        )
                    self._event_bus.publish(
                        "routine.run.status",
                        {"routine_id": routine_id, "run": run_obj},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
                    self._start_routine_task(
                        routine=routine,
                        run=run_obj,
                        thread_id=thread_id,
                        skip_auto_review=True,
                    )
        else:
            if (
                isinstance(pending_ctx, dict)
                and isinstance(pending_ctx.get("routine_id"), str)
                and isinstance(pending_ctx.get("routine_run_id"), str)
            ):
                routine_id = str(pending_ctx["routine_id"])
                routine_run_id = str(pending_ctx["routine_run_id"])
                decision_past = (
                    "denied"
                    if decision == "deny"
                    else "skipped"
                    if decision == "skip"
                    else f"{decision}ed"
                )
                with contextlib.suppress(StoreNotFoundError):
                    denied_run = self._store.update_routine_run(
                        routine_run_id,
                        {
                            "status": "failed",
                            "error": f"Routine paused for approval was {decision_past}.",
                            "finished_at": utc_iso_now(),
                        },
                    )
                    self._event_bus.publish(
                        "routine.run.status",
                        {"routine_id": routine_id, "run": denied_run},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
            if run_id_raw:
                run_id = str(run_id_raw)
                try:
                    await maybe_await(
                        self._coordinator.cancel_task(run_id, reason=f"operator_{decision}")
                    )
                except (KeyError, InvalidStateTransitionError):
                    pass
                except Exception:  # noqa: BLE001
                    logger.exception("Failed cancelling runtime run %s on %s", run_id, decision)

            subtext = "Action denied" if decision == "deny" else "Action skipped"
            self._emit_presence(
                bot_id,
                state="idle",
                subtext=subtext,
                computer_active=False,
                thread_id=thread_id,
                needs_attention=self._store.count_pending_approvals_for_bot(bot_id) > 0,
            )
            bot = self._store.get_bot(bot_id)
            bot_name = str(bot["name"]) if bot is not None else "Bot"
            ack_msg = self._store.create_message(
                thread_id=thread_id,
                sender_type="bot",
                sender_bot_id=bot_id,
                sender_name=bot_name,
                content=f"Understood — I did not proceed with **{approval['title']}** ({subtext}).",
                status="done",
            )
            self._event_bus.publish(
                "message.completed",
                {"message_id": ack_msg["id"], "message": ack_msg},
                bot_id=bot_id,
                thread_id=thread_id,
            )

    def _start_runtime_resume(
        self,
        *,
        approval: dict[str, Any],
        run_id: str,
        decision: str,
        pending_ctx: dict[str, Any],
    ) -> str:
        """Schedule runtime HITL resumption as a tracked, interruptible background task."""
        thread_id = str(approval["thread_id"])
        prev_task = self._active_tasks.get(thread_id)
        if prev_task is not None and not prev_task.done():
            prev_task.cancel()
        extra_routine_tasks: list[asyncio.Task[None]] = []
        popped_routines = self._thread_routine_tasks.pop(thread_id, {})
        for (r_id, rr_id), r_task in popped_routines.items():
            if not r_task.done():
                r_task.cancel()
                if r_task is not prev_task:
                    extra_routine_tasks.append(r_task)
            self._fail_interrupted_routine_run(
                r_id,
                rr_id,
                thread_id=thread_id,
                error="Routine superseded by runtime resume.",
            )
        prev_routine_ref = self._active_routine_runs.pop(thread_id, None)
        if prev_routine_ref is not None:
            self._fail_interrupted_routine_run(
                prev_routine_ref[0],
                prev_routine_ref[1],
                thread_id=thread_id,
                error="Runtime resume superseded by new turn.",
            )

        turn_id = f"trn_{uuid.uuid4().hex[:12]}"
        self._active_turns[thread_id] = turn_id
        self._active_runtime_runs[thread_id] = run_id
        routine_id = (
            str(pending_ctx["routine_id"]).strip()
            if isinstance(pending_ctx.get("routine_id"), str)
            and str(pending_ctx["routine_id"]).strip()
            else None
        )
        routine_run_id = (
            str(pending_ctx["routine_run_id"]).strip()
            if isinstance(pending_ctx.get("routine_run_id"), str)
            and str(pending_ctx["routine_run_id"]).strip()
            else None
        )
        if routine_run_id:
            self._active_routine_runs[thread_id] = (routine_id, routine_run_id)

        task = asyncio.create_task(
            self._resume_and_stream_runtime_run_serialized(
                previous_task=prev_task,
                extra_previous_tasks=tuple(extra_routine_tasks),
                approval=approval,
                run_id=run_id,
                decision=decision,
                pending_ctx=pending_ctx,
                turn_id=turn_id,
            )
        )
        self._active_tasks[thread_id] = task
        if routine_id:
            self._routine_tasks_by_routine.setdefault(routine_id, set()).add(task)
            self._routine_coord_runs.setdefault(routine_id, set()).add(run_id)

        def _cleanup(done_task: asyncio.Task[None]) -> None:
            if routine_id:
                r_set = self._routine_tasks_by_routine.get(routine_id)
                if r_set is not None:
                    r_set.discard(done_task)
                    if not r_set:
                        self._routine_tasks_by_routine.pop(routine_id, None)
                c_set = self._routine_coord_runs.get(routine_id)
                if c_set is not None:
                    c_set.discard(run_id)
                    if not c_set:
                        self._routine_coord_runs.pop(routine_id, None)
            if self._active_tasks.get(thread_id) is done_task:
                self._active_tasks.pop(thread_id, None)
            if self._active_turns.get(thread_id) == turn_id:
                self._active_turns.pop(thread_id, None)
            if self._active_runtime_runs.get(thread_id) == run_id:
                self._active_runtime_runs.pop(thread_id, None)
            if routine_run_id and self._active_routine_runs.get(thread_id) == (
                routine_id,
                routine_run_id,
            ):
                self._active_routine_runs.pop(thread_id, None)

        task.add_done_callback(_cleanup)
        return turn_id

    async def _resume_and_stream_runtime_run_serialized(
        self,
        *,
        previous_task: asyncio.Task[None] | None,
        extra_previous_tasks: tuple[asyncio.Task[None], ...] = (),
        approval: dict[str, Any],
        run_id: str,
        decision: str,
        pending_ctx: dict[str, Any],
        turn_id: str,
    ) -> None:
        thread_id = str(approval["thread_id"])
        if previous_task is not None and not previous_task.done():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await previous_task
        for extra_task in extra_previous_tasks:
            if not extra_task.done():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await extra_task

        async with self._get_thread_lock(thread_id):
            if self._active_turns.get(thread_id) != turn_id:
                return
            await self._resume_and_stream_runtime_run(
                approval=approval,
                run_id=run_id,
                decision=decision,
                pending_ctx=pending_ctx,
                turn_id=turn_id,
            )

    async def _resume_and_stream_runtime_run(
        self,
        *,
        approval: dict[str, Any],
        run_id: str,
        decision: str,
        pending_ctx: dict[str, Any],
        turn_id: str | None = None,
    ) -> None:
        bot_id = str(approval["bot_id"])
        thread_id = str(approval["thread_id"])
        routine_id = (
            str(pending_ctx["routine_id"])
            if isinstance(pending_ctx.get("routine_id"), str) and pending_ctx.get("routine_id")
            else None
        )
        routine_run_id = (
            str(pending_ctx["routine_run_id"])
            if isinstance(pending_ctx.get("routine_run_id"), str)
            and pending_ctx.get("routine_run_id")
            else None
        )
        if routine_id and routine_run_id:
            with contextlib.suppress(StoreNotFoundError):
                running_rtn = self._store.update_routine_run(
                    routine_run_id,
                    {"status": "running", "error": None},
                )
                self._event_bus.publish(
                    "routine.run.status",
                    {"routine_id": routine_id, "run": running_rtn},
                    bot_id=bot_id,
                    thread_id=thread_id,
                )
        bot = self._store.get_bot(bot_id)
        bot_name = str(bot["name"]) if bot is not None else "Bot"
        model_id = str(bot.get("model_id") or "") if bot is not None else ""
        turn_id = turn_id or f"trn_{uuid.uuid4().hex[:12]}"

        assistant_msg = self._store.create_message(
            thread_id=thread_id,
            sender_type="bot",
            sender_bot_id=bot_id,
            sender_name=bot_name,
            content="",
            model_id=model_id,
            status="streaming",
        )
        msg_id = str(assistant_msg["id"])

        self._event_bus.publish(
            "turn.started",
            {
                "turn_id": turn_id,
                "message_id": msg_id,
                "model_id": model_id,
                "engine_id": "controlbot_runtime",
                "sender_bot_id": bot_id,
                "sender_name": bot_name,
            },
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        self._emit_presence(
            bot_id,
            state="working",
            subtext="Resuming runtime task...",
            computer_active=False,
            step_label="ControlBot Runtime",
            thread_id=thread_id,
            turn_id=turn_id,
        )

        seen_receipts: set[str] = {str(r) for r in pending_ctx.get("seen_receipts", [])}
        tool_calls: list[dict[str, Any]] = []
        self._active_runtime_runs[thread_id] = run_id

        try:
            await maybe_await(
                self._coordinator.resume_task(
                    run_id,
                    {
                        "approval_decision": decision,
                        "approved": True,
                        "reauthenticated": True,
                    },
                )
            )
            snapshot = await self._await_runtime_run(
                run_id,
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=msg_id,
                seen_receipts=seen_receipts,
                tool_calls=tool_calls,
            )

            if snapshot is not None and snapshot.run.status == TaskStatus.WAITING_FOR_INPUT:
                next_pending_ctx: dict[str, Any] = {
                    "run_id": run_id,
                    "bot_id": bot_id,
                    "thread_id": thread_id,
                    "seen_receipts": sorted(seen_receipts),
                }
                if routine_id and routine_run_id:
                    next_pending_ctx["routine_id"] = routine_id
                    next_pending_ctx["routine_run_id"] = routine_run_id
                appr = self._store.create_approval(
                    bot_id=bot_id,
                    thread_id=thread_id,
                    kind="standard",
                    title=str(snapshot.run.required_action or "Runtime input required")[:240],
                    target=f"run:{run_id}",
                    arguments={"run_id": run_id},
                    pending_context=next_pending_ctx,
                )
                self._event_bus.publish(
                    "hitl.approval.requested",
                    {"approval": appr},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                answer = (
                    f"Run `{run_id}` is waiting for operator input: "
                    f"{snapshot.run.required_action or 'approval required'}."
                )
                self._event_bus.publish(
                    "message.delta",
                    {"message_id": msg_id, "text_delta": answer},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                self._finalize_pages_and_message(
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    message_id=msg_id,
                    content=answer,
                    tool_calls=tool_calls,
                    conversation_id=None,
                    status="done",
                )
                req_action = snapshot.run.required_action or "input required"
                if routine_id and routine_run_id:
                    with contextlib.suppress(StoreNotFoundError):
                        waiting_rtn = self._store.update_routine_run(
                            routine_run_id,
                            {
                                "status": "waiting_approval",
                                "summary": (
                                    f"Routine paused for operator input "
                                    f"(run `{run_id}`): {req_action}."
                                )[:1000],
                            },
                        )
                        self._event_bus.publish(
                            "routine.run.status",
                            {"routine_id": routine_id, "run": waiting_rtn},
                            bot_id=bot_id,
                            thread_id=thread_id,
                        )
                self._emit_presence(
                    bot_id,
                    state="waiting_human",
                    subtext=f"Waiting for approval: {req_action}"[:120],
                    computer_active=False,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    needs_attention=True,
                )
                return

            if snapshot is not None and snapshot.run.status == TaskStatus.CANCELLED and (
                snapshot.run.transition_reason == "interrupted_by_operator"
                or self._active_turns.get(thread_id) != turn_id
            ):
                cur_msg = self._store.get_message(msg_id)
                if cur_msg is not None and cur_msg.get("status") == "streaming":
                    updated = self._store.update_message(msg_id, {"status": "interrupted"})
                    self._event_bus.publish(
                        "message.completed",
                        {"message_id": msg_id, "message": updated},
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
                if routine_id and routine_run_id:
                    finished_at = utc_iso_now()
                    with contextlib.suppress(StoreNotFoundError):
                        self._store.update_routine(routine_id, {"last_run_at": finished_at})
                        failed_rtn = self._store.update_routine_run(
                            routine_run_id,
                            {
                                "status": "failed",
                                "error": "Runtime resume interrupted by operator.",
                                "finished_at": finished_at,
                            },
                        )
                        self._event_bus.publish(
                            "routine.run.status",
                            {"routine_id": routine_id, "run": failed_rtn},
                            bot_id=bot_id,
                            thread_id=thread_id,
                        )
                self._emit_presence(
                    bot_id,
                    state="idle",
                    subtext="Interrupted by operator",
                    computer_active=False,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                return

            final_status = "done"
            verified_meta: dict[str, Any] | None = None
            if snapshot is not None and snapshot.run.status in TERMINAL_TASK_STATUSES:
                if snapshot.result is not None and snapshot.result.answer:
                    answer = snapshot.result.answer
                else:
                    answer = (
                        f"ControlBot Runtime run `{run_id}` finished with status "
                        f"`{snapshot.run.status.value}` ({snapshot.run.transition_reason})."
                    )
                if snapshot.run.status == TaskStatus.FAILED:
                    final_status = "error"
                    p_info = snapshot.result.partial_info if snapshot.result is not None else None
                    answer = _format_runtime_error_message(answer, p_info)
                verified_meta = self._build_runtime_meta(snapshot, lane=Lane.INDUSTRIAL)
            else:
                cur_status = snapshot.run.status.value if snapshot is not None else "running"
                answer = f"Resumed run `{run_id}` (status: `{cur_status}`)."

            self._event_bus.publish(
                "message.delta",
                {"message_id": msg_id, "text_delta": answer},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=msg_id,
                content=answer,
                tool_calls=tool_calls,
                conversation_id=None,
                status=final_status,
                metadata=verified_meta,
            )
            if routine_id and routine_run_id:
                finished_at = utc_iso_now()
                with contextlib.suppress(StoreNotFoundError):
                    self._store.update_routine(routine_id, {"last_run_at": finished_at})
                    if final_status == "error" or (
                        snapshot is not None and snapshot.run.status == TaskStatus.CANCELLED
                    ):
                        rtn_updates: dict[str, Any] = {
                            "status": "failed",
                            "error": answer[:1000],
                            "finished_at": finished_at,
                        }
                    else:
                        rtn_updates = {
                            "status": "succeeded",
                            "summary": answer[:1000],
                            "message_id": msg_id,
                            "finished_at": finished_at,
                        }
                    done_rtn = self._store.update_routine_run(routine_run_id, rtn_updates)
                    self._event_bus.publish(
                        "routine.run.status",
                        {"routine_id": routine_id, "run": done_rtn},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
            self._emit_presence(
                bot_id,
                state="idle" if final_status == "done" else "error",
                subtext="Nothing is blocked" if final_status == "done" else "Runtime resume failed",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
        except asyncio.CancelledError:
            with contextlib.suppress(StoreNotFoundError):
                cur_msg = self._store.get_message(msg_id)
                if cur_msg is not None and cur_msg.get("status") == "streaming":
                    updated = self._store.update_message(msg_id, {"status": "interrupted"})
                    self._event_bus.publish(
                        "message.completed",
                        {"message_id": msg_id, "message": updated},
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
            if routine_id and routine_run_id:
                finished_at = utc_iso_now()
                with contextlib.suppress(StoreNotFoundError):
                    self._store.update_routine(routine_id, {"last_run_at": finished_at})
                    failed_rtn = self._store.update_routine_run(
                        routine_run_id,
                        {
                            "status": "failed",
                            "error": "Runtime resume interrupted by operator.",
                            "finished_at": finished_at,
                        },
                    )
                    self._event_bus.publish(
                        "routine.run.status",
                        {"routine_id": routine_id, "run": failed_rtn},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="Interrupted by operator",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to resume runtime run %s", run_id)
            err_msg = str(scrub_v1_payload(str(exc)))[:400]
            updated = self._store.update_message(
                msg_id,
                {
                    "content": f"Failed to resume runtime run `{run_id}`: {err_msg}",
                    "status": "error",
                },
            )
            self._event_bus.publish(
                "message.completed",
                {"message_id": msg_id, "message": updated},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            if routine_id and routine_run_id:
                finished_at = utc_iso_now()
                with contextlib.suppress(StoreNotFoundError):
                    self._store.update_routine(routine_id, {"last_run_at": finished_at})
                    failed_rtn = self._store.update_routine_run(
                        routine_run_id,
                        {
                            "status": "failed",
                            "error": err_msg[:1000],
                            "finished_at": finished_at,
                        },
                    )
                    self._event_bus.publish(
                        "routine.run.status",
                        {"routine_id": routine_id, "run": failed_rtn},
                        bot_id=bot_id,
                        thread_id=thread_id,
                    )
            self._emit_presence(
                bot_id,
                state="error",
                subtext=err_msg[:120],
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
        finally:
            if self._active_runtime_runs.get(thread_id) == run_id:
                self._active_runtime_runs.pop(thread_id, None)
            if routine_run_id and self._active_routine_runs.get(thread_id) == (
                routine_id,
                routine_run_id,
            ):
                self._active_routine_runs.pop(thread_id, None)

    # ------------------------------------------------------------------
    # Mentions, Prompt Building & Draft Delivery
    # ------------------------------------------------------------------

    def _resolve_target_bots(
        self,
        thread_id: str,
        user_message: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], bool]:
        bot = self._store.get_bot_by_thread(thread_id)
        if bot is not None:
            return [bot], False

        channel = self._store.get_channel_by_thread(thread_id)
        if channel is None:
            return [], False

        channel_bots: list[dict[str, Any]] = []
        for bid in channel["bot_ids"]:
            found = self._store.get_bot(str(bid))
            if found is not None:
                channel_bots.append(found)
        if not channel_bots:
            return [], True

        content = str(user_message.get("content", ""))
        content_low = content.lower()
        explicit_mentions = [
            str(m).strip().lstrip("@").rstrip(".,:;!?").lower()
            for m in user_message.get("mentions", [])
            if str(m).strip()
        ]
        inline_mentions = _extract_inline_mentions(content)

        if (
            "all" in inline_mentions
            or "everyone" in inline_mentions
            or "all" in explicit_mentions
            or "everyone" in explicit_mentions
        ):
            return channel_bots, True

        matched: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for candidate in channel_bots:
            cid = str(candidate["id"])
            name_low = str(candidate["name"]).strip().lower()
            exact_aliases = {cid.lower()} | _slug_variants(name_low)
            full_name_boundary = bool(
                name_low
                and re.search(rf"(?<!\S)@{re.escape(name_low)}(?=$|[\s,.:;!?])", content_low)
            )
            is_mentioned = (
                full_name_boundary
                or any(m in exact_aliases for m in explicit_mentions)
                or any(m in exact_aliases for m in inline_mentions)
            )
            if is_mentioned and cid not in seen_ids:
                seen_ids.add(cid)
                matched.append(candidate)

        if matched:
            return matched, True

        # Secondary fallback on unambiguous first word (e.g. @Chief -> Chief of Staff)
        first_word_matched: list[dict[str, Any]] = []
        for candidate in channel_bots:
            cid = str(candidate["id"])
            name_low = str(candidate["name"]).strip().lower()
            parts = name_low.split()
            first_word = parts[0] if parts else ""
            if (
                first_word
                and (first_word in explicit_mentions or first_word in inline_mentions)
                and cid not in seen_ids
            ):
                seen_ids.add(cid)
                first_word_matched.append(candidate)

        if first_word_matched:
            return first_word_matched, True

        primary = next((b for b in channel_bots if b.get("is_primary")), channel_bots[0])
        return [primary], True

    def _build_memory_section(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        query: str,
        project_id: str | None = None,
    ) -> str | None:
        if self._memory_store is None:
            return None
        mem = self._memory_store
        bot_id = str(bot["id"])
        resolved_project = (
            project_id.strip()
            if isinstance(project_id, str) and project_id.strip()
            else (str(bot.get("project_name") or "").strip() or None)
        )
        raw_section = ""

        try:
            if hasattr(mem, "build_context_injection"):
                access_ctx = MemoryAccessContext(
                    user_id="operator",
                    agent_role=bot_id,
                    thread_id=thread_id,
                    project_area=resolved_project,
                )
                bundle = mem.build_context_injection(access_ctx, query=query)
                raw_section = str(getattr(bundle, "combined_text", "") or "")
                if not raw_section.strip() and hasattr(mem, "search_memories"):
                    hits = mem.search_memories(access_ctx, query, limit=8)
                    lines: list[str] = ["[MEMORY CONTEXT]"]
                    for item in list(hits or [])[:8]:
                        if not isinstance(item, dict):
                            continue
                        kind = item.get("kind", "note")
                        obs_at = item.get("observed_at", "")
                        valid_until = item.get("valid_until", "")
                        title = item.get("title", "")
                        body = item.get("content", "")
                        lines.append(
                            f"[MEMORY kind={kind} observed_at={obs_at} valid_until={valid_until} "
                            f"authority=advisory_only]\n{title}: {body}"
                        )
                    if len(lines) > 1:
                        raw_section = "\n\n".join(lines)
            elif hasattr(mem, "build_prompt_context"):
                built = mem.build_prompt_context(
                    query=query,
                    user_id="operator",
                    agent_role=bot_id,
                    thread_id=thread_id,
                    project_id=resolved_project,
                    max_chars=_MEMORY_PROMPT_MAX_CHARS,
                )
                raw_section = str(built or "")
            elif hasattr(mem, "search"):
                hits = mem.search(
                    query=query,
                    agent_role=bot_id,
                    thread_id=thread_id,
                    project_id=resolved_project,
                )
                lines = ["[MEMORY CONTEXT]"]
                for item in list(hits or [])[:8]:
                    if not isinstance(item, dict):
                        continue
                    kind = item.get("kind", "note")
                    obs_at = item.get("observed_at", "")
                    valid_until = item.get("valid_until", "")
                    title = item.get("title", "")
                    body = item.get("content", "")
                    lines.append(
                        f"[MEMORY kind={kind} observed_at={obs_at} valid_until={valid_until} "
                        f"authority=advisory_only]\n{title}: {body}"
                    )
                if len(lines) > 1:
                    raw_section = "\n\n".join(lines)
        except Exception:  # noqa: BLE001
            logger.exception("Optional memory_store context lookup failed")
            return None

        if not raw_section.strip():
            return None
        scrubbed = str(scrub_v1_payload(raw_section))
        if len(scrubbed) > _MEMORY_PROMPT_MAX_CHARS:
            scrubbed = scrubbed[: _MEMORY_PROMPT_MAX_CHARS - 3] + "..."
        return scrubbed

    def _build_bot_prompt(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        user_message: dict[str, Any],
        skill_ids: list[str],
        thinking_level: str,
        handoff_context: str | None = None,
        page_context_id: str | None = None,
        airlock_context: str | None = None,
        airlock_sanitize: Callable[[str], str] | None = None,
        project_id: str | None = None,
    ) -> str:
        sections: list[str] = []
        role_prompt = str(bot.get("role_prompt", "")).strip()
        bot_name = str(bot.get("name", ""))
        if airlock_sanitize is not None:
            bot_name = airlock_sanitize(bot_name) or "Assistant"
            if role_prompt:
                role_prompt = airlock_sanitize(role_prompt)
        if role_prompt:
            sections.append(f"[BOT PERSONA: {bot_name}]\n{role_prompt}")

        # Resolve @skill mentions and explicit skill_ids (with hyphen/underscore normalization)
        all_skills = self._store.list_skills(str(bot["id"]))
        content = str(user_message.get("content", ""))
        inline_mentions = set(_extract_inline_mentions(content))
        wanted_skill_ids = set(skill_ids)
        applied_skills: list[dict[str, Any]] = []
        for skill in all_skills:
            skill_aliases = _slug_variants(str(skill["slug"])) | _slug_variants(str(skill["name"]))
            if str(skill["id"]) in wanted_skill_ids or bool(skill_aliases & inline_mentions):
                applied_skills.append(skill)
        if applied_skills:
            skill_lines = ["[ACTIVE SKILLS]"]
            for skl in applied_skills:
                skill_name = str(skl["name"])
                skill_content = str(skl["content_md"])
                if airlock_sanitize is not None:
                    skill_name = airlock_sanitize(skill_name) or "Skill"
                    skill_content = airlock_sanitize(skill_content)
                skill_lines.append(f"## Skill: {skill_name}\n{skill_content}")
            sections.append("\n\n".join(skill_lines))

        # Include attachment metadata and scrubbed text previews
        attachments = user_message.get("attachments")
        if isinstance(attachments, list) and attachments:
            att_lines = ["[ATTACHMENTS]"]
            for att in attachments:
                if not isinstance(att, dict):
                    continue
                att_id = str(att.get("id", ""))
                fname = str(att.get("filename", "file"))
                if airlock_sanitize is not None:
                    fname = airlock_sanitize(fname) or "file"
                mime = str(att.get("mime_type", "application/octet-stream"))
                size = int(att.get("size_bytes", 0))
                att_lines.append(f"- {fname} ({mime}, {size} bytes)")
                rec = self._store.get_attachment_record(att_id) if att_id else None
                if rec is not None and (
                    mime.startswith("text/")
                    or any(mime.endswith(suf) for suf in ("json", "xml", "yaml", "markdown"))
                ):
                    fpath = Path(str(rec["storage_path"]))
                    if fpath.is_file():
                        with contextlib.suppress(OSError):
                            raw = fpath.read_bytes()[:4096]
                            if b"\x00" not in raw:
                                preview = str(
                                    scrub_v1_payload(raw.decode("utf-8", errors="replace"))
                                )
                                if airlock_sanitize is not None:
                                    preview = airlock_sanitize(preview)
                                att_lines.append(f"  Preview:\n```\n{preview}\n```")
            sections.append("\n".join(att_lines))

        if handoff_context:
            sections.append(f"[CHANNEL HANDOFF CONTEXT]\n{handoff_context}")

        if airlock_context:
            sections.append(f"[SANITIZED PLANT SPECS (AIRLOCK)]\n{airlock_context}")

        # Active Page Context injection (authorized scope check)
        resolved_page_id = _extract_page_context_id(user_message, page_context_id)
        if resolved_page_id:
            page = self._store.get_artifact(resolved_page_id)
            if page is not None and page.get("type") == "page":
                is_authorized = (
                    page.get("share_scope") in {"team", "public"}
                    or str(page.get("bot_id")) == str(bot["id"])
                    or str(page.get("thread_id")) == thread_id
                )
                if is_authorized:
                    page_title = str(page.get("title", ""))
                    page_md = str(scrub_v1_payload(str(page.get("content_md") or "")))
                    if airlock_sanitize is not None:
                        page_title = airlock_sanitize(page_title)
                        page_md = airlock_sanitize(page_md)
                    if len(page_md) > _PAGE_CONTEXT_MAX_CHARS:
                        page_md = page_md[: _PAGE_CONTEXT_MAX_CHARS - 3] + "..."
                    sections.append(
                        f"[ACTIVE PAGE CONTEXT]\n"
                        f"Title: {page_title}\n"
                        f"Page ID: {page.get('id', '')} (v{page.get('version', 1)})\n\n"
                        f"{page_md}"
                    )

        if thinking_level != "medium":
            sections.append(f"[REASONING DEPTH: {thinking_level}]")

        sections.append(
            "[OUTPUT FORMAT HINT]\n"
            "When creating a structured standalone document, report, or brief, wrap it in:\n"
            ':::page{title="Document Title"}\n<markdown content>\n:::'
        )

        shell_policy_lines = [
            "[EXECUTION & SHELL POLICY]",
            "- When calling run_command/bash, NEVER use command substitution ($(...) or "
            "backticks), process substitution (<(...) or >(...)), eval, exec, pipe-to-shell "
            "(| sh / | bash), or chained rm (&& rm / ; rm); ControlBot PolicyGateway blocks "
            "those shell patterns and aborts the turn.",
            "- Use plain commands, standard pipes (|), or python3 -c / standalone scripts instead "
            "(for example, never write VAR=$(curl ...); use curl ... | grep ... or python3).",
        ]
        if (
            airlock_sanitize is None
            and self._live_browser is not None
            and self._is_app_enabled("app_playwright")
        ):
            local_base = _default_local_base_url()
            shell_policy_lines.append(
                f"- To open or show a webpage in ControlBot Studio's live browser panel, call "
                f"POST {local_base}/api/browser/action with "
                f'{{"type":"navigate","url":"https://..."}} '
                f"(starts the browser automatically if stopped) and inspect it via "
                f"GET {local_base}/api/browser/context. "
                f"Whenever the user asks to show, open, or browse a website or product in the "
                f"browser, you MUST call POST {local_base}/api/browser/action so the Live Browser "
                f"panel on the right opens automatically inside ControlBot Studio; do not merely "
                f"paste an external link. If a target site blocks this server region (e.g. HTTP "
                f"403 / region restricted), explain that clearly and open an accessible product, "
                f"datasheet, or search page in the live browser instead."
            )
        sections.append("\n".join(shell_policy_lines))

        # Memory placed right before [USER MESSAGE] so persona/skills prefix remains KV-cacheable
        mem_section = self._build_memory_section(
            bot=bot,
            thread_id=thread_id,
            query=content,
            project_id=project_id,
        )
        if mem_section:
            if airlock_sanitize is not None:
                mem_section = airlock_sanitize(mem_section)
            if mem_section:
                sections.append(mem_section)

        sections.append(f"[USER MESSAGE]\n{content}")
        return "\n\n".join(sections)

    def _resolve_vault_secret_value(
        self,
        *,
        secret_id: str | None = None,
        secret_name: str | None = None,
        bot_id: str | None = None,
        preferred_keys: tuple[str, ...],
    ) -> tuple[str | None, str | None]:
        ref_id = (secret_id or "").strip()
        ref_name = (secret_name or "").strip()
        if not ref_id and not ref_name:
            return None, None

        candidates = self._store.list_vault_secrets(bot_id=bot_id or None)
        meta: dict[str, Any] | None = None
        if ref_id:
            meta = next((item for item in candidates if str(item.get("id")) == ref_id), None)
        elif ref_name:
            meta = next(
                (item for item in candidates if str(item.get("name", "")).strip() == ref_name),
                None,
            )

        if meta is None:
            return None, f"Referenced Vault secret not found or unauthorized: {ref_id or ref_name}"
        meta_bot_id = meta.get("bot_id")
        if meta_bot_id is not None and bot_id and str(meta_bot_id) != str(bot_id):
            return None, "Referenced Vault secret does not belong to this bot."

        decrypted = self._store.decrypt_vault_secret(str(meta["id"]))
        if not isinstance(decrypted, dict) or not decrypted:
            return None, f"Vault secret {meta['id']} could not be decrypted or is empty."

        for key in preferred_keys:
            val = str(decrypted.get(key) or "").strip()
            if val and val != "[REDACTED]":
                return val, None

        for key, raw_val in decrypted.items():
            if str(key).lower() in {"username", "user", "email", "login", "url", "webhook_url"}:
                continue
            val = str(raw_val or "").strip()
            if val and val != "[REDACTED]":
                return val, None

        return None, f"Vault secret {meta['id']} does not contain a usable secret field."

    def _resolve_smtp_settings(self) -> dict[str, Any] | None:
        cfg: dict[str, Any] | None = None
        if self._smtp_config and self._smtp_config.get("host"):
            cfg = dict(self._smtp_config)
        else:
            settings = self._store.get_settings()
            if isinstance(settings.get("smtp"), dict) and settings["smtp"].get("host"):
                cfg = dict(settings["smtp"])
        if cfg is not None:
            raw_pw = str(cfg.get("password") or "").strip()
            if not raw_pw or raw_pw == "[REDACTED]":
                pw_secret_id = str(
                    cfg.get("smtp_password_secret_id")
                    or cfg.get("password_secret_id")
                    or cfg.get("secret_id")
                    or ""
                ).strip()
                pw_secret_name = str(
                    cfg.get("smtp_password_secret_name") or cfg.get("secret_name") or ""
                ).strip()
                if pw_secret_id or pw_secret_name:
                    resolved_pw, _err = self._resolve_vault_secret_value(
                        secret_id=pw_secret_id or None,
                        secret_name=pw_secret_name or None,
                        preferred_keys=(
                            "password",
                            "smtp_password",
                            "secret",
                            "secret_value",
                            "value",
                        ),
                    )
                    if resolved_pw:
                        cfg["password"] = resolved_pw
            return cfg
        host = os.environ.get("CONTROLBOT_SMTP_HOST", "").strip()
        if not host:
            return None
        port_raw = os.environ.get("CONTROLBOT_SMTP_PORT", "587").strip()
        try:
            port = int(port_raw)
        except ValueError:
            port = 587
        use_tls_raw = os.environ.get("CONTROLBOT_SMTP_USE_TLS", "true").strip().lower()
        return {
            "host": host,
            "port": port,
            "username": os.environ.get("CONTROLBOT_SMTP_USER", "").strip() or None,
            "password": os.environ.get("CONTROLBOT_SMTP_PASSWORD", "").strip() or None,
            "from_addr": os.environ.get("CONTROLBOT_SMTP_FROM", "").strip() or None,
            "use_tls": use_tls_raw in {"1", "true", "yes", "on"},
            "use_ssl": os.environ.get("CONTROLBOT_SMTP_USE_SSL", "").strip().lower()
            in {"1", "true", "yes", "on"},
        }

    def _resolve_webhook_config_with_error(
        self,
        fields: dict[str, Any],
        *,
        bot_id: str = "",
    ) -> tuple[str | None, str | None, str | None]:
        direct_url = str(fields.get("webhook_url") or "").strip()
        app = self._get_connected_app("app_webhooks")
        app_cfg: dict[str, Any] = (
            dict(app["config"]) if app is not None and isinstance(app.get("config"), dict) else {}
        )
        cfg_url = str(
            app_cfg.get("draft_webhook_url") or app_cfg.get("webhook_url") or ""
        ).strip()
        env_url = os.environ.get("CONTROLBOT_DRAFT_WEBHOOK_URL", "").strip()
        resolved_url = direct_url or cfg_url or env_url or None

        secret_pref_keys = (
            "webhook_secret",
            "hmac_secret",
            "signing_secret",
            "secret",
            "secret_value",
            "password",
            "value",
            "token",
        )

        # 1. Direct unredacted field (in-memory pre-scrub draft)
        raw_field_secret = str(fields.get("webhook_secret") or "").strip()
        if raw_field_secret and raw_field_secret != "[REDACTED]":
            return resolved_url, raw_field_secret, None

        # 2. Explicit Vault secret ref on draft fields
        field_sec_id = str(
            fields.get("webhook_secret_id")
            or fields.get("vault_secret_id")
            or fields.get("secret_id")
            or ""
        ).strip()
        field_sec_name = str(
            fields.get("webhook_secret_name") or fields.get("secret_name") or ""
        ).strip()
        if field_sec_id or field_sec_name:
            val, err = self._resolve_vault_secret_value(
                secret_id=field_sec_id or None,
                secret_name=field_sec_name or None,
                bot_id=bot_id or None,
                preferred_keys=secret_pref_keys,
            )
            return resolved_url, val, err

        # 3. Runtime-injected webhook_secrets (by URL, bot_id, app_webhooks, or default)
        for key in (resolved_url or "", bot_id, "app_webhooks", "default"):
            if key and key in self._webhook_secrets:
                return resolved_url, self._webhook_secrets[key], None

        # 4. Unredacted app_webhooks config secret (if present)
        raw_cfg_secret = str(app_cfg.get("webhook_secret") or "").strip()
        if raw_cfg_secret and raw_cfg_secret != "[REDACTED]":
            return resolved_url, raw_cfg_secret, None

        # 5. Vault secret ref in app_webhooks config
        cfg_sec_id = str(
            app_cfg.get("webhook_secret_id")
            or app_cfg.get("vault_secret_id")
            or app_cfg.get("secret_id")
            or app_cfg.get("secret_ref")
            or ""
        ).strip()
        cfg_sec_name = str(
            app_cfg.get("webhook_secret_name") or app_cfg.get("secret_name") or ""
        ).strip()
        if cfg_sec_id or cfg_sec_name:
            val, err = self._resolve_vault_secret_value(
                secret_id=cfg_sec_id or None,
                secret_name=cfg_sec_name or None,
                bot_id=bot_id or None,
                preferred_keys=secret_pref_keys,
            )
            return resolved_url, val, err

        # 6. Environment variable fallback
        env_secret = os.environ.get("CONTROLBOT_DRAFT_WEBHOOK_SECRET", "").strip()
        if env_secret and env_secret != "[REDACTED]":
            return resolved_url, env_secret, None

        # 7. Fail closed if a secret was configured and scrubbed to [REDACTED]
        if raw_field_secret == "[REDACTED]" or raw_cfg_secret == "[REDACTED]":
            return (
                resolved_url,
                None,
                "Webhook secret was redacted by store; store it in Vault and set "
                "'webhook_secret_id' on app_webhooks, or configure webhook_secrets / "
                "CONTROLBOT_DRAFT_WEBHOOK_SECRET.",
            )

        return resolved_url, None, None

    def _resolve_webhook_config(self, fields: dict[str, Any]) -> tuple[str | None, str | None]:
        url, secret, _err = self._resolve_webhook_config_with_error(fields)
        return url, secret

    async def deliver_draft(self, draft: dict[str, Any]) -> dict[str, Any]:
        """Deliver approved draft via HTTP Webhook or SMTP, or fall back cleanly."""
        fields = dict(draft.get("fields") or {})
        channel_type = str(draft.get("channel_type") or "email").lower()
        draft_id = str(draft.get("id") or "")
        bot_id = str(draft.get("bot_id") or "")
        thread_id = str(draft.get("thread_id") or "")

        webhook_url, webhook_secret, webhook_secret_error = self._resolve_webhook_config_with_error(
            fields,
            bot_id=bot_id,
        )
        smtp_cfg = self._resolve_smtp_settings()

        # 1. Webhook transport
        if webhook_url and (fields.get("webhook_url") or channel_type in {"webhook", "slack", "x"}):
            if not self._is_app_enabled("app_webhooks"):
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "error": "Routine Webhooks app is disabled in Connected Apps.",
                }
            try:
                webhook_url = EgressGuard(
                    allow_loopback_for_tests=self._allow_loopback_webhooks
                ).validate_url(webhook_url)
            except EgressBlockedError as exc:
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "error": f"Blocked draft webhook URL (SSRF policy): {exc}",
                }
            if webhook_secret_error:
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "error": webhook_secret_error,
                }
            decision = self._policy_gateway.evaluate_and_record(
                PolicyRequest(
                    actor_id=bot_id or "runner",
                    actor_role="bot",
                    lane=Lane.GENERAL,
                    tool_id="draft.deliver_webhook",
                    action_kind="write",
                    arguments={"draft_id": draft_id, "webhook_url": webhook_url},
                )
            )
            if not decision.allowed:
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "error": f"Blocked by PolicyGateway: {decision.reason}",
                }
            body_bytes = json.dumps(
                {
                    "draft_id": draft_id,
                    "bot_id": bot_id,
                    "thread_id": thread_id,
                    "channel_type": channel_type,
                    "fields": scrub_v1_payload(fields),
                },
                sort_keys=True,
            ).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if webhook_secret:
                sig = hmac.new(
                    webhook_secret.encode("utf-8"),
                    body_bytes,
                    hashlib.sha256,
                ).hexdigest()
                headers["X-ControlBot-Signature"] = f"sha256={sig}"

            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client:
                    resp = await client.post(
                        webhook_url,
                        content=body_bytes,
                        headers=headers,
                        follow_redirects=False,
                    )
                if 200 <= resp.status_code < 300:
                    return {
                        "delivered": True,
                        "transport": "webhook",
                        "status_code": resp.status_code,
                    }
                if 300 <= resp.status_code < 400:
                    return {
                        "delivered": False,
                        "transport": "webhook",
                        "status_code": resp.status_code,
                        "error": f"Blocked webhook redirect response (HTTP {resp.status_code})",
                    }
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "status_code": resp.status_code,
                    "error": f"Webhook returned HTTP {resp.status_code}",
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "delivered": False,
                    "transport": "webhook",
                    "error": str(scrub_v1_payload(str(exc)))[:240],
                }

        # 2. SMTP email transport
        if channel_type == "email" and smtp_cfg is not None:
            decision = self._policy_gateway.evaluate_and_record(
                PolicyRequest(
                    actor_id=bot_id or "runner",
                    actor_role="bot",
                    lane=Lane.GENERAL,
                    tool_id="draft.deliver_smtp",
                    action_kind="write",
                    arguments={
                        "draft_id": draft_id,
                        "to": fields.get("to"),
                        "subject": fields.get("subject"),
                    },
                )
            )
            if not decision.allowed:
                return {
                    "delivered": False,
                    "transport": "smtp",
                    "error": f"Blocked by PolicyGateway: {decision.reason}",
                }

            to_addr = str(fields.get("to") or "").strip()
            if not to_addr:
                return {
                    "delivered": False,
                    "transport": "smtp",
                    "error": "Draft email missing recipient 'to' address.",
                }

            try:
                msg = EmailMessage()
                from_addr = str(
                    fields.get("from") or smtp_cfg.get("from_addr") or "controlbot@localhost"
                )
                subject_val = str(fields.get("subject") or "ControlBot Draft")
                cc_val = str(fields["cc"]) if fields.get("cc") else None
                bcc_val = str(fields["bcc"]) if fields.get("bcc") else None
                for hdr_name, hdr_val in (
                    ("from", from_addr),
                    ("to", to_addr),
                    ("cc", cc_val),
                    ("bcc", bcc_val),
                    ("subject", subject_val),
                ):
                    if hdr_val is not None and ("\r" in hdr_val or "\n" in hdr_val):
                        raise ValueError(
                            f"Invalid CR/LF characters in email header '{hdr_name}'."
                        )
                msg["From"] = from_addr
                msg["To"] = to_addr
                if cc_val is not None:
                    msg["Cc"] = cc_val
                if bcc_val is not None:
                    msg["Bcc"] = bcc_val
                msg["Subject"] = subject_val
                msg.set_content(str(fields.get("body") or ""))

                # Safe attachment resolution strictly within self._uploads_dir
                uploads_root = self._uploads_dir.resolve()
                for att_name in list(fields.get("attachments") or []):
                    cand = (uploads_root / str(att_name)).resolve()
                    if cand.is_file() and cand.is_relative_to(uploads_root):
                        msg.add_attachment(
                            cand.read_bytes(),
                            maintype="application",
                            subtype="octet-stream",
                            filename=cand.name,
                        )

                def _send_smtp() -> None:
                    host = str(smtp_cfg["host"])
                    port = int(smtp_cfg.get("port", 25))
                    timeout = float(smtp_cfg.get("timeout", 10.0))
                    if smtp_cfg.get("use_ssl"):
                        with smtplib.SMTP_SSL(host, port, timeout=timeout) as srv:
                            if smtp_cfg.get("username") and smtp_cfg.get("password"):
                                srv.login(str(smtp_cfg["username"]), str(smtp_cfg["password"]))
                            srv.send_message(msg)
                    else:
                        with smtplib.SMTP(host, port, timeout=timeout) as srv:
                            if smtp_cfg.get("use_tls"):
                                srv.starttls()
                            if smtp_cfg.get("username") and smtp_cfg.get("password"):
                                srv.login(str(smtp_cfg["username"]), str(smtp_cfg["password"]))
                            srv.send_message(msg)

                await asyncio.to_thread(_send_smtp)
                return {
                    "delivered": True,
                    "transport": "smtp",
                    "recipient": to_addr,
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "delivered": False,
                    "transport": "smtp",
                    "error": str(scrub_v1_payload(str(exc)))[:240],
                }

        return {
            "delivered": False,
            "transport": "none",
            "reason": "no_transport_configured",
        }

    async def on_draft_resolved(
        self,
        draft: dict[str, Any],
        *,
        action: str,
    ) -> dict[str, Any]:
        """Execute draft delivery on 'send' and emit scrubbed chat feedback when attempted."""
        if action != "send":
            return {"delivered": False, "transport": "none", "reason": f"action_{action}"}

        delivery = await self.deliver_draft(draft)
        if delivery.get("transport") != "none":
            bot_id = str(draft.get("bot_id") or "")
            thread_id = str(draft.get("thread_id") or "")
            bot = self._store.get_bot(bot_id) if bot_id else None
            bot_name = str(bot["name"]) if bot is not None else "Bot"
            if delivery.get("delivered"):
                content = f"Delivered draft `{draft.get('id')}` via **{delivery['transport']}**."
                msg_status = "done"
            else:
                safe_err = scrub_v1_payload(str(delivery.get("error") or "Delivery failed"))
                content = (
                    f"Failed to deliver draft `{draft.get('id')}` via "
                    f"**{delivery['transport']}**: {safe_err}"
                )
                msg_status = "error"
            if thread_id and bot_id:
                posted = self._store.create_message(
                    thread_id=thread_id,
                    sender_type="bot",
                    sender_bot_id=bot_id,
                    sender_name=bot_name,
                    content=content,
                    status=msg_status,
                )
                self._event_bus.publish(
                    "message.completed",
                    {"message_id": posted["id"], "message": posted, "delivery": delivery},
                    bot_id=bot_id,
                    thread_id=thread_id,
                )
        return delivery

    async def _maybe_handle_hitl_slash_command(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        turn_id: str,
        content: str,
    ) -> bool:
        stripped = content.strip()
        bot_id = str(bot["id"])
        if stripped.startswith("/approval "):
            title = stripped[len("/approval ") :].strip() or "Confirm requested action"
            appr = self._store.create_approval(
                bot_id=bot_id,
                thread_id=thread_id,
                kind="standard",
                title=title[:240],
                target="vm:default",
                risk_banner="Operator confirmation required before proceeding.",
                arguments={"requested_via": "slash_command", "title": title[:240]},
            )
            self._emit_presence(
                bot_id,
                state="waiting_human",
                subtext="Waiting for your approval",
                thread_id=thread_id,
                turn_id=turn_id,
                needs_attention=True,
            )
            self._event_bus.publish(
                "hitl.approval.requested",
                {"approval": appr},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return True

        if stripped.startswith("/draft-send "):
            draft_id = stripped[len("/draft-send ") :].strip()
            if draft_id:
                updated = self._store.resolve_draft(draft_id, "send")
                self._event_bus.publish(
                    "hitl.draft.updated",
                    {"draft": updated},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                await self.on_draft_resolved(updated, action="send")
                return True

        if stripped.startswith("/draft "):
            rest = stripped[len("/draft ") :].strip()
            parts = [p.strip() for p in rest.split("|")]
            to_addr = parts[0] if len(parts) >= 1 and parts[0] else "ops@example.com"
            subject = parts[1] if len(parts) >= 2 and parts[1] else "Workspace Update"
            body = parts[2] if len(parts) >= 3 else rest
            draft = self._store.create_draft(
                bot_id=bot_id,
                thread_id=thread_id,
                channel_type="email",
                fields={
                    "from": f"{bot['name'].lower().replace(' ', '.')}@controlbot.local",
                    "to": to_addr,
                    "bcc": "",
                    "subject": subject,
                    "body": body,
                    "attachments": [],
                    "remove_signature": False,
                },
            )
            self._event_bus.publish(
                "hitl.draft.created",
                {"draft": draft},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return True

        if stripped.startswith("/secure-form"):
            domain = stripped[len("/secure-form") :].strip() or "example.com"
            form = self._store.create_secure_form(
                bot_id=bot_id,
                thread_id=thread_id,
                kind="form",
                domain=domain,
                title=f"Sign in to {domain}",
                fields=[
                    {"name": "username", "label": "Username or email", "secret": False},
                    {"name": "password", "label": "Password", "secret": True},
                ],
                allow_vault_save=True,
            )
            self._event_bus.publish(
                "hitl.secure_form.requested",
                {"form": form},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return True

        return False

    # ------------------------------------------------------------------
    # Thread Turn Execution
    # ------------------------------------------------------------------

    async def _run_thread_turn(
        self,
        *,
        thread_id: str,
        turn_id: str,
        user_message: dict[str, Any],
        include_browser_context: bool | None,
        model_id: str | None,
        thinking_level: str | None,
        skill_ids: list[str],
        skip_auto_review: bool,
        page_context_id: str | None = None,
        ui_lane: Lane | None = None,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> None:
        target_bots, is_channel = self._resolve_target_bots(thread_id, user_message)
        if not target_bots:
            if is_channel:
                err_msg = self._store.create_message(
                    thread_id=thread_id,
                    sender_type="bot",
                    sender_bot_id=None,
                    sender_name="System",
                    content="Channel has no active bots to handle this message.",
                    status="error",
                )
                self._event_bus.publish(
                    "message.completed",
                    {"message_id": err_msg["id"], "message": err_msg},
                    bot_id=None,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
            return

        content = str(user_message.get("content", ""))

        # Hard safety_floor check before anything executes
        floor_violation = safety_floor("turn.prompt", {"prompt": content})
        if floor_violation is not None:
            lead_bot = target_bots[0]
            lead_id = str(lead_bot["id"])
            self._policy_gateway.evaluate_and_record(
                PolicyRequest(
                    actor_id=lead_id,
                    actor_role="bot",
                    lane=Lane.GENERAL,
                    tool_id="turn.prompt",
                    action_kind="write",
                    arguments={"prompt": content},
                    task_id=turn_id,
                )
            )
            meta = VerifiedResponseMeta(
                verdict=VerdictState.CONTRADICTED,
                lane=Lane.GENERAL,
                domain_profile="general_office",
                degraded_banner=f"Blocked by PolicyGateway safety floor ({floor_violation}).",
            ).model_dump(mode="json")
            blocked_msg = self._store.create_message(
                thread_id=thread_id,
                sender_type="bot",
                sender_bot_id=lead_id,
                sender_name=str(lead_bot["name"]),
                content=f"Action blocked by safety floor: `{floor_violation}`.",
                status="error",
            )
            updated_blocked = (
                self._store.update_message(str(blocked_msg["id"]), {"metadata": meta})
                or {**blocked_msg, "metadata": meta}
            )
            if "metadata" not in updated_blocked:
                updated_blocked = {**updated_blocked, "metadata": meta}
            self._event_bus.publish(
                "message.completed",
                {
                    "message_id": updated_blocked["id"],
                    "message": updated_blocked,
                },
                bot_id=lead_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._emit_presence(
                lead_id,
                state="idle",
                subtext="Blocked by safety floor",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return

        # Auto-review ask_first check before invoking engines
        if not skip_auto_review:
            rules = self._store.list_auto_review_rules()
            matched_rule = _match_ask_first_rule(content, rules)
            if matched_rule is not None:
                lead_bot = target_bots[0]
                lead_id = str(lead_bot["id"])
                appr = self._store.create_approval(
                    bot_id=lead_id,
                    thread_id=thread_id,
                    kind="ask_first",
                    title=f"Confirm action: {matched_rule[:120]}",
                    target=f"bot:{lead_id}",
                    risk_banner="This can't be undone",
                    arguments={
                        "prompt": content[:500],
                        "matched_rule": matched_rule,
                    },
                    allow_always_allowed=True,
                    pending_context={
                        "thread_id": thread_id,
                        "user_message": user_message,
                        "bot_id": lead_id,
                        "include_browser_context": include_browser_context,
                        "model_id": model_id,
                        "thinking_level": thinking_level,
                        "skill_ids": skill_ids,
                        "page_context_id": page_context_id,
                        "facility_id": facility_id,
                        "allowed_areas": list(allowed_areas) if allowed_areas else [],
                    },
                )
                self._emit_presence(
                    lead_id,
                    state="waiting_human",
                    subtext="Waiting for approval (Ask First)",
                    thread_id=thread_id,
                    turn_id=turn_id,
                    needs_attention=True,
                )
                self._event_bus.publish(
                    "hitl.approval.requested",
                    {"approval": appr},
                    bot_id=lead_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                return

        if await self._maybe_handle_hitl_slash_command(
            bot=target_bots[0],
            thread_id=thread_id,
            turn_id=turn_id,
            content=content,
        ):
            return

        try:
            effective_scope = self._resolve_runtime_scope(
                facility_id=facility_id,
                allowed_areas=allowed_areas,
                user_message=user_message,
            )
        except ValueError as exc:
            lead_bot = target_bots[0]
            lead_id = str(lead_bot["id"])
            err_msg = self._store.create_message(
                thread_id=thread_id,
                sender_type="bot",
                sender_bot_id=lead_id,
                sender_name=str(lead_bot["name"]),
                content=f"Invalid runtime scope: {scrub_v1_payload(str(exc))}",
                status="error",
            )
            self._event_bus.publish(
                "message.completed",
                {"message_id": err_msg["id"], "message": err_msg},
                bot_id=lead_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._emit_presence(
                lead_id,
                state="error",
                subtext="Invalid runtime scope",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return

        # 2-Stage LaneRouter classification
        route_decision = await self._router.route(
            content,
            ui_lane=ui_lane,
            facility_config=self._resolve_facility_config(),
            area=(
                effective_scope.allowed_areas[0]
                if len(effective_scope.allowed_areas) == 1
                else None
            ),
            allowed_areas=effective_scope.allowed_areas,
        )
        if route_decision.needs_clarification:
            lead_bot = target_bots[0]
            lead_id = str(lead_bot["id"])
            cand_dicts = [
                c.model_dump(mode="json") for c in route_decision.clarification_candidates
            ]
            meta = VerifiedResponseMeta(
                verdict=VerdictState.NEEDS_CLARIFICATION,
                lane=route_decision.lane,
                domain_profile=route_decision.domain_profile,
                clarification_candidates=[
                    {k: str(v) for k, v in item.items() if v is not None} for item in cand_dicts
                ],
            ).model_dump(mode="json")
            cand_lines = "\n".join(
                f"- **{c.canonical_label}** (`{c.asset_id}`, area `{c.area or 'unspecified'}`)"
                for c in route_decision.clarification_candidates
            )
            clar_body = (
                f"Clarification needed before running OT tools ({route_decision.rationale})."
                + (f"\n\nCandidates:\n{cand_lines}" if cand_lines else "")
                + "\n\nReply with the exact asset/area or confirm running as general web research."
            )
            clar_msg = self._store.create_message(
                thread_id=thread_id,
                sender_type="bot",
                sender_bot_id=lead_id,
                sender_name=str(lead_bot["name"]),
                content=clar_body,
                status="done",
            )
            with contextlib.suppress(Exception):
                updated_clar = self._store.update_message(clar_msg["id"], {"metadata": meta})
                clar_msg = updated_clar
            self._event_bus.publish(
                "message.completed",
                {
                    "message_id": clar_msg["id"],
                    "message": {**clar_msg, "metadata": meta},
                },
                bot_id=lead_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._emit_presence(
                lead_id,
                state="idle",
                subtext="Waiting for clarification",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return

        handoff_context: str | None = None
        for idx, bot in enumerate(target_bots):
            if idx > 0:
                prev_bot = target_bots[idx - 1]
                summary = (handoff_context or "Continuing multi-bot workflow")[:240]
                self._event_bus.publish(
                    "handoff.dispatched",
                    {
                        "from_bot_id": str(prev_bot["id"]),
                        "to_bot_id": str(bot["id"]),
                        "from_name": str(prev_bot["name"]),
                        "to_name": str(bot["name"]),
                        "summary": summary,
                    },
                    bot_id=str(bot["id"]),
                    thread_id=thread_id,
                    turn_id=turn_id,
                )

            response_text = await self._run_single_bot_turn(
                bot=bot,
                thread_id=thread_id,
                turn_id=turn_id,
                user_message=user_message,
                is_channel=is_channel,
                include_browser_context=include_browser_context,
                model_id=model_id,
                thinking_level=thinking_level,
                skill_ids=skill_ids,
                handoff_context=handoff_context,
                page_context_id=page_context_id,
                route_decision=route_decision,
                facility_id=facility_id,
                allowed_areas=allowed_areas,
            )
            if response_text:
                handoff_context = f"{bot['name']} responded:\n{response_text[:1500]}"

    async def _run_single_bot_turn(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        turn_id: str,
        user_message: dict[str, Any],
        is_channel: bool,
        include_browser_context: bool | None,
        model_id: str | None,
        thinking_level: str | None,
        skill_ids: list[str],
        handoff_context: str | None,
        page_context_id: str | None = None,
        route_decision: RouteDecision | None = None,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> str:
        bot_id = str(bot["id"])
        bot_name = str(bot["name"])
        settings = self._store.get_settings()
        engine_id = str(bot.get("engine_id") or settings.get("default_engine_id") or "agy")
        default_model = str(settings.get("default_model_id") or "gemini-4-carbon-low")
        resolved_model = str(model_id or bot.get("model_id") or default_model)
        resolved_thinking = str(thinking_level or bot.get("thinking_level") or "medium")
        use_browser = (
            include_browser_context
            if include_browser_context is not None
            else bool(settings.get("include_browser_context", True))
        )

        self._emit_presence(
            bot_id,
            state="acknowledging",
            subtext="Thinking...",
            computer_active=False,
            thread_id=thread_id,
            turn_id=turn_id,
        )

        assistant_msg = self._store.create_message(
            thread_id=thread_id,
            sender_type="bot",
            sender_bot_id=bot_id,
            sender_name=bot_name,
            content="",
            model_id=resolved_model,
            conversation_id=None if is_channel else bot.get("conversation_id"),
            status="streaming",
        )
        msg_id = str(assistant_msg["id"])

        self._event_bus.publish(
            "turn.started",
            {
                "turn_id": turn_id,
                "message_id": msg_id,
                "model_id": resolved_model,
                "engine_id": engine_id,
                "sender_bot_id": bot_id,
                "sender_name": bot_name,
            },
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )

        try:
            # Mixed lane flow: Industrial read -> EvidenceAirlock -> General prompt
            if route_decision is not None and route_decision.lane == Lane.MIXED:
                return await self._execute_mixed_lane_turn(
                    bot=bot,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    message_id=msg_id,
                    user_message=user_message,
                    engine_id=engine_id,
                    resolved_model=resolved_model,
                    resolved_thinking=resolved_thinking,
                    skill_ids=skill_ids,
                    handoff_context=handoff_context,
                    page_context_id=page_context_id,
                    allow_hydrogen=bool(settings.get("allow_hydrogen", False)),
                    use_browser=use_browser,
                    is_channel=is_channel,
                    route_decision=route_decision,
                    facility_id=facility_id,
                    allowed_areas=allowed_areas,
                )

            if engine_id == "controlbot_runtime":
                return await self._execute_runtime_engine(
                    bot=bot,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    message_id=msg_id,
                    prompt=str(user_message.get("content", "")),
                    lane=route_decision.lane if route_decision else Lane.INDUSTRIAL,
                    user_message=user_message,
                    resolved_model=resolved_model,
                    resolved_thinking=resolved_thinking,
                    skill_ids=skill_ids,
                    handoff_context=handoff_context,
                    page_context_id=page_context_id,
                    allow_hydrogen=bool(settings.get("allow_hydrogen", False)),
                    use_browser=use_browser,
                    is_channel=is_channel,
                    facility_id=facility_id,
                    allowed_areas=allowed_areas,
                )

            effective_prompt = self._build_bot_prompt(
                bot=bot,
                thread_id=thread_id,
                user_message=user_message,
                skill_ids=skill_ids,
                thinking_level=resolved_thinking,
                handoff_context=handoff_context,
                page_context_id=page_context_id,
            )
            return await self._execute_agy_engine(
                bot=bot,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=msg_id,
                prompt=effective_prompt,
                model_id=resolved_model,
                allow_hydrogen=bool(settings.get("allow_hydrogen", False)),
                use_browser_context=use_browser,
                is_channel=is_channel,
                lane=route_decision.lane if route_decision else Lane.GENERAL,
            )
        except asyncio.CancelledError:
            with contextlib.suppress(StoreNotFoundError):
                updated = self._store.update_message(msg_id, {"status": "interrupted"})
                self._event_bus.publish(
                    "message.completed",
                    {"message_id": msg_id, "message": updated},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="Interrupted",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Error executing single bot turn %s", turn_id)
            err_msg = str(scrub_v1_payload(str(exc)))[:400]
            updated = self._store.update_message(
                msg_id,
                {"content": f"Error executing turn: {err_msg}", "status": "error"},
            )
            self._event_bus.publish(
                "message.completed",
                {"message_id": msg_id, "message": updated},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._emit_presence(
                bot_id,
                state="error",
                subtext=err_msg[:120],
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

    def _sanitize_text_via_airlock(
        self,
        text: str,
        *,
        blocked_ids: Sequence[str],
        task_id: str,
    ) -> str:
        if not text.strip():
            return ""
        scrubbed = str(scrub_v1_payload(text))
        res = self._airlock.project(
            {"manufacturer": scrubbed},
            blocked_identifiers=blocked_ids,
            task_id=task_id,
        )
        return res.spec.manufacturer or ""

    def _sanitize_browser_context_via_airlock(
        self,
        browser_ctx: dict[str, Any],
        airlock_sanitize: Callable[[str], str] | None = None,
        *,
        blocked_ids: Sequence[str] = (),
        task_id: str | None = None,
    ) -> dict[str, Any]:
        sanitize_fn: Callable[[str], str] = airlock_sanitize or (
            lambda txt: self._sanitize_text_via_airlock(
                txt,
                blocked_ids=blocked_ids,
                task_id=task_id or "browser-airlock",
            )
        )

        def _scrub_node(node: Any) -> Any:
            if isinstance(node, str):
                scrubbed = str(scrub_v1_payload(node))
                return sanitize_fn(scrubbed)
            if isinstance(node, Mapping):
                out: dict[str, Any] = {}
                for k, v in node.items():
                    clean_k = sanitize_fn(str(scrub_v1_payload(str(k))))
                    out[clean_k] = _scrub_node(v)
                return out
            if isinstance(node, list):
                return [_scrub_node(item) for item in node]
            if isinstance(node, tuple):
                return [_scrub_node(item) for item in node]
            return node

        pre_scrubbed = scrub_v1_payload(browser_ctx)
        sanitized = _scrub_node(pre_scrubbed)
        if not isinstance(sanitized, dict):
            raise AirlockBlockedError(
                "EvidenceAirlock fail-closed block: invalid sanitized browser_context structure."
            )

        serialized = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
        final_proj = self._airlock.project(
            {"manufacturer": str(scrub_v1_payload(serialized))},
            blocked_identifiers=blocked_ids,
            task_id=task_id,
        )
        if final_proj.stripped_tokens_count > 0:
            raise AirlockBlockedError(
                "EvidenceAirlock fail-closed block: residual sensitive tokens "
                "detected in mixed-lane browser_context."
            )
        return sanitized

    async def _execute_mixed_lane_turn(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        turn_id: str,
        message_id: str,
        user_message: dict[str, Any],
        engine_id: str,
        resolved_model: str,
        resolved_thinking: str,
        skill_ids: list[str],
        handoff_context: str | None,
        page_context_id: str | None,
        allow_hydrogen: bool,
        use_browser: bool,
        is_channel: bool,
        route_decision: RouteDecision,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> str:
        """Execute Industrial read -> EvidenceAirlock projection -> General synthesis."""
        bot_id = str(bot["id"])
        raw_query = str(user_message.get("content", ""))

        blocked_ids_set: set[str] = set()
        resolved_fac_cfg = self._resolve_facility_config()
        if resolved_fac_cfg is not None:
            for val in (resolved_fac_cfg.facility_id, resolved_fac_cfg.facility_name):
                if val and len(val.strip()) >= 2:
                    blocked_ids_set.add(val.strip())
            for area_id, area_cfg in resolved_fac_cfg.areas.items():
                for val in (area_id, area_cfg.display_name):
                    if val and len(val.strip()) >= 2:
                        blocked_ids_set.add(val.strip())
            for asset in resolved_fac_cfg.assets:
                for val in (
                    asset.asset_id,
                    asset.canonical_label,
                    *asset.aliases,
                    *asset.source_ids.values(),
                ):
                    if val and len(val.strip()) >= 2:
                        blocked_ids_set.add(val.strip())
        blocked_ids = sorted(blocked_ids_set)

        plant_facts: list[str] = []
        raw_industrial_payload: dict[str, Any] = {
            "query": raw_query,
            "manufacturer": user_message.get("manufacturer"),
            "model": user_message.get("model"),
            "device_category": user_message.get("device_category"),
            "sensor_type": user_message.get("sensor_type"),
            "output_signal": user_message.get("output_signal"),
            "process_range": user_message.get("process_range"),
        }

        if self._is_app_enabled("app_runtime"):
            task_spec = TaskSpec(
                task_id=f"mix-{uuid.uuid4().hex[:10]}",
                user_id="operator",
                profile_id="default",
                scope=self._resolve_runtime_scope(
                    facility_id=facility_id,
                    allowed_areas=allowed_areas,
                    user_message=user_message,
                ),
                query=raw_query or "Inspect equipment specs",
            )
            run = await maybe_await(self._coordinator.submit_task(task_spec))
            self._active_runtime_runs[thread_id] = run.run_id
            try:
                snap = await self._await_runtime_run(
                    run.run_id,
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    message_id=None,
                    seen_receipts=set(),
                    tool_calls=[],
                    timeout_s=30.0,
                )
            finally:
                if self._active_runtime_runs.get(thread_id) == run.run_id:
                    self._active_runtime_runs.pop(thread_id, None)
            if snap is not None and snap.result is not None:
                if snap.result.answer:
                    plant_facts.append(snap.result.answer)
                for obs in snap.result.verified_observations:
                    plant_facts.append(
                        f"{obs.source}: {obs.observed_label}={obs.value} {obs.unit or ''}".strip()
                    )
                    for spec_k in (
                        "manufacturer",
                        "model",
                        "device_category",
                        "sensor_type",
                        "input_signal",
                        "output_signal",
                        "supply_voltage",
                        "process_range",
                        "mounting",
                    ):
                        if obs.metadata.get(spec_k) and not raw_industrial_payload.get(spec_k):
                            raw_industrial_payload[spec_k] = obs.metadata[spec_k]

        try:
            projection = self._airlock.project(
                raw_industrial_payload,
                blocked_identifiers=blocked_ids,
                task_id=turn_id,
            )
        except AirlockBlockedError as exc:
            err_meta = VerifiedResponseMeta(
                verdict=VerdictState.CONTRADICTED,
                lane=Lane.MIXED,
                domain_profile=route_decision.domain_profile,
                degraded_banner=str(exc),
            ).model_dump(mode="json")
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=f"Evidence Airlock blocked unsafe plant-to-web projection: {exc}",
                tool_calls=[],
                conversation_id=None,
                status="error",
                metadata=err_meta,
            )
            self._emit_presence(
                bot_id,
                state="error",
                subtext="EvidenceAirlock blocked turn",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        airlock_provenance: AirlockProvenance = build_airlock_provenance(
            plant_facts=plant_facts or ["Local plant read-only verification"],
            web_facts=["Sanitized public equipment specification ready for external search"],
            airlock_audit_id=projection.audit_id,
            projected_spec=projection.spec,
        )

        if engine_id == "controlbot_runtime" or find_agy_executable() is None:
            combined = (
                f"**Planta (verificado, vía Airlock `{projection.audit_id}`):**\n"
                + (
                    "\n".join(f"- {f}" for f in plant_facts)
                    if plant_facts
                    else "- Especificación técnica sanitizada"
                )
                + (
                    "\n\n**Especificación pública proyectada (sin tags/IPs/costos internos):**\n"
                    f"{projection.sanitized_summary}"
                )
            )
            meta = VerifiedResponseMeta(
                verdict=VerdictState.VERIFIED,
                lane=Lane.MIXED,
                domain_profile=route_decision.domain_profile,
                agreements=tuple(plant_facts),
                airlock_provenance=airlock_provenance,
            ).model_dump(mode="json")
            self._event_bus.publish(
                "message.delta",
                {"message_id": message_id, "text_delta": combined},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=combined,
                tool_calls=[],
                conversation_id=None,
                status="done",
                metadata=meta,
            )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="Nothing is blocked",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return combined

        def airlock_sanitize_fn(txt: str) -> str:
            return self._sanitize_text_via_airlock(
                txt,
                blocked_ids=blocked_ids,
                task_id=turn_id,
            )

        try:
            sanitized_query = airlock_sanitize_fn(raw_query)
            sanitized_handoff = airlock_sanitize_fn(handoff_context) if handoff_context else None
            sanitized_user_message = {**user_message, "content": sanitized_query}
            effective_prompt = self._build_bot_prompt(
                bot=bot,
                thread_id=thread_id,
                user_message=sanitized_user_message,
                skill_ids=skill_ids,
                thinking_level=resolved_thinking,
                handoff_context=sanitized_handoff,
                page_context_id=page_context_id,
                airlock_context=projection.sanitized_summary,
                airlock_sanitize=airlock_sanitize_fn,
            )
            final_proj = self._airlock.project(
                {"manufacturer": str(scrub_v1_payload(effective_prompt))},
                blocked_identifiers=blocked_ids,
                task_id=turn_id,
            )
            if final_proj.stripped_tokens_count > 0:
                raise AirlockBlockedError(
                    "EvidenceAirlock fail-closed block: residual sensitive tokens "
                    "detected in mixed-lane prompt."
                )
            return await self._execute_agy_engine(
                bot=bot,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                prompt=effective_prompt,
                model_id=resolved_model,
                allow_hydrogen=allow_hydrogen,
                use_browser_context=use_browser,
                is_channel=is_channel,
                lane=Lane.MIXED,
                airlock_provenance=airlock_provenance,
                airlock_sanitize=airlock_sanitize_fn,
                blocked_ids=blocked_ids,
            )
        except AirlockBlockedError as exc:
            err_meta = VerifiedResponseMeta(
                verdict=VerdictState.CONTRADICTED,
                lane=Lane.MIXED,
                domain_profile=route_decision.domain_profile,
                degraded_banner=str(exc),
            ).model_dump(mode="json")
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=f"Evidence Airlock blocked unsafe plant-to-web prompt: {exc}",
                tool_calls=[],
                conversation_id=None,
                status="error",
                metadata=err_meta,
            )
            self._emit_presence(
                bot_id,
                state="error",
                subtext="EvidenceAirlock blocked turn",
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

    def _finalize_pages_and_message(
        self,
        *,
        bot_id: str,
        thread_id: str,
        turn_id: str,
        message_id: str,
        content: str,
        tool_calls: list[dict[str, Any]],
        conversation_id: str | None,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        artifacts_summary: list[dict[str, Any]] = []
        for title, page_md in extract_page_blocks(content):
            art, supersedes_msg_id = self._store.create_or_version_page(
                bot_id=bot_id,
                title=title,
                content_md=page_md,
                thread_id=thread_id,
                message_id=message_id,
            )
            artifacts_summary.append(
                {
                    "id": art["id"],
                    "type": art["type"],
                    "title": art["title"],
                    "version": art["version"],
                    "superseded_by_id": art["superseded_by_id"],
                }
            )
            self._event_bus.publish(
                "artifact.page.updated",
                {
                    "artifact": art,
                    "supersedes_message_id": supersedes_msg_id,
                },
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )

        update_payload: dict[str, Any] = {
            "content": content,
            "tool_calls": tool_calls,
            "artifacts": artifacts_summary,
            "conversation_id": conversation_id,
            "status": status,
        }
        if metadata is not None:
            update_payload["metadata"] = metadata

        updated = self._store.update_message(message_id, update_payload)
        sse_msg = (
            {**updated, "metadata": metadata}
            if metadata is not None and "metadata" not in updated
            else updated
        )
        self._event_bus.publish(
            "message.completed",
            {"message_id": message_id, "message": sse_msg},
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        return sse_msg

    def _gate_mid_turn_tool_with_status(
        self,
        *,
        bot_id: str,
        turn_id: str,
        lane: Lane,
        tool_name: str,
        category: str,
        summary: str,
        command: str | None = None,
        commands: Sequence[str] | None = None,
        allow_incomplete_syntax: bool = False,
    ) -> tuple[bool, str | None, bool]:
        """Enforce ConnectedApps, takeover lock, safety_floor, and PolicyGateway with deferral."""
        cmd_candidates: list[str] = []
        seen_cands: set[str] = set()
        if isinstance(command, str) and command.strip():
            c_clean = command.strip()
            seen_cands.add(c_clean)
            cmd_candidates.append(c_clean)
        for cand in commands or ():
            if isinstance(cand, str):
                c_clean = cand.strip()
                if c_clean and c_clean not in seen_cands:
                    seen_cands.add(c_clean)
                    cmd_candidates.append(c_clean)
        primary_cmd = cmd_candidates[0] if cmd_candidates else None
        has_command = bool(cmd_candidates)
        if has_command or _infer_tool_category(tool_name, command=primary_cmd) == "terminal":
            category = "terminal"
        if category == "browser" and not self._is_app_enabled("app_playwright"):
            return False, "Playwright Browser app is disabled in Connected Apps.", False
        if category == "terminal" and not self._is_app_enabled("app_pty"):
            return False, "Workspace Terminal (PTY) app is disabled in Connected Apps.", False
        action_kind = _infer_action_kind(
            tool_name,
            category,
            known_read_only_mcp_tools=self._known_read_only_mcp_tools,
            command=primary_cmd,
        )
        if (
            category == "files"
            and action_kind == "write"
            and not self._is_app_enabled("app_files")
        ):
            return False, "Workspace Files app is disabled in Connected Apps.", False

        if (
            category == "browser"
            and self._computer_gateway is not None
            and hasattr(self._computer_gateway, "is_human_takeover")
            and self._computer_gateway.is_human_takeover("default")
        ):
            return False, "Blocked: Human takeover lock is active on computer session.", False

        is_mcp = _is_mcp_tool(tool_name)
        mcp_known_ro = (
            is_mcp
            and not has_command
            and tool_name.strip().lower() in self._known_read_only_mcp_tools
        )
        req_action_kind: Literal["read", "write", "unknown_mcp"] = (
            ("read" if mcp_known_ro else "unknown_mcp")
            if is_mcp
            else ("write" if action_kind == "write" else "read")
        )
        syntax_deferred = False
        if category == "terminal":
            if allow_incomplete_syntax:
                if cmd_candidates:
                    parseable_cmds: list[str] = []
                    destructive_variants: list[str] = []
                    any_deferred = False
                    for cand in cmd_candidates:
                        floor_violation = safety_floor(tool_name, {"command": cand})
                        if floor_violation is not None and floor_violation.startswith(
                            "safety_floor:unparseable_shell_syntax"
                        ):
                            destructive_variant = _find_unquoted_safety_variant(tool_name, cand)
                            if destructive_variant is not None:
                                destructive_variants.append(destructive_variant)
                                parseable_cmds.append(cand)
                            else:
                                any_deferred = True
                        else:
                            parseable_cmds.append(cand)
                    if destructive_variants:
                        policy_args: dict[str, Any] = {
                            "normalized_command": destructive_variants[0],
                            "command": parseable_cmds[0],
                        }
                        if len(destructive_variants) > 1:
                            policy_args["normalized_commands"] = destructive_variants
                        if len(parseable_cmds) > 1:
                            policy_args["commands"] = parseable_cmds
                    elif parseable_cmds:
                        policy_args = {"command": parseable_cmds[0]}
                        if len(parseable_cmds) > 1:
                            policy_args["commands"] = parseable_cmds
                        if any_deferred:
                            syntax_deferred = True
                    else:
                        syntax_deferred = True
                        policy_args = {"deferred": True}
                else:
                    summary_text = summary.strip()
                    summary_violation = (
                        safety_floor(tool_name, {"summary": summary})
                        if summary_text
                        else None
                    )
                    if summary_violation is not None:
                        if not summary_violation.startswith(
                            "safety_floor:unparseable_shell_syntax"
                        ):
                            policy_args = {"summary": summary}
                        else:
                            destructive_variant = _find_unquoted_safety_variant(
                                tool_name, summary_text
                            )
                            if destructive_variant is not None:
                                policy_args = {
                                    "normalized_command": destructive_variant,
                                    "summary": summary,
                                }
                            else:
                                syntax_deferred = True
                                policy_args = {"deferred": True}
                    else:
                        syntax_deferred = True
                        policy_args = {"deferred": True}
            else:
                if cmd_candidates:
                    policy_args = {"command": cmd_candidates[0]}
                    if len(cmd_candidates) > 1:
                        policy_args["commands"] = cmd_candidates
                else:
                    policy_args = {"summary": summary, "command": summary}
        else:
            policy_args = {"summary": summary}

        decision = self._policy_gateway.evaluate_and_record(
            PolicyRequest(
                actor_id=bot_id,
                actor_role="bot",
                lane=lane,
                tool_id=tool_name,
                action_kind=req_action_kind,
                arguments=policy_args,
                is_mcp_tool=is_mcp,
                mcp_known_read_only=mcp_known_ro,
                task_id=turn_id,
            )
        )
        if not decision.allowed:
            return False, f"Blocked by PolicyGateway ({decision.reason})", False
        return True, None, syntax_deferred

    def _gate_mid_turn_tool(
        self,
        *,
        bot_id: str,
        turn_id: str,
        lane: Lane,
        tool_name: str,
        category: str,
        summary: str,
        command: str | None = None,
        commands: Sequence[str] | None = None,
        allow_incomplete_syntax: bool = False,
    ) -> tuple[bool, str | None]:
        """Enforce ConnectedApp toggles, human takeover lock, safety_floor, and PolicyGateway."""
        allowed, block_reason, _ = self._gate_mid_turn_tool_with_status(
            bot_id=bot_id,
            turn_id=turn_id,
            lane=lane,
            tool_name=tool_name,
            category=category,
            summary=summary,
            command=command,
            commands=commands,
            allow_incomplete_syntax=allow_incomplete_syntax,
        )
        return allowed, block_reason

    def gate_agy_stream_tool_event(
        self,
        *,
        ev: Mapping[str, Any],
        bot_id: str,
        turn_id: str,
        lane: Lane = Lane.GENERAL,
        pending_syntax_tools: dict[str, dict[str, Any]],
        tool_state_by_call: dict[str, dict[str, Any]],
        active_unnamed_calls_by_tool: dict[str, str],
        existing_call_ids: set[str] | None = None,
    ) -> tuple[bool, str | None, dict[str, Any]]:
        """Gate a streamed `agy` tool event through ConnectedApps, safety_floor & PolicyGateway."""
        tool_name = str(ev.get("tool_name") or ev.get("name") or "tool")
        raw_state = str(ev.get("state") or ev.get("status") or "ACTIVE").upper()
        is_terminal_state = raw_state in {
            "DONE",
            "COMPLETED",
            "SUCCESS",
            "ERROR",
            "FAILED",
        }
        raw_step_idx = ev.get("step_index")
        parsed_step_idx: int | None = None
        if isinstance(raw_step_idx, int) and not isinstance(raw_step_idx, bool):
            parsed_step_idx = raw_step_idx
        elif isinstance(raw_step_idx, str) and raw_step_idx.strip():
            with contextlib.suppress(ValueError):
                parsed_step_idx = int(raw_step_idx.strip())

        if parsed_step_idx is not None:
            call_id = f"tc_{parsed_step_idx}"
        else:
            existing_unnamed = active_unnamed_calls_by_tool.get(tool_name)
            if existing_unnamed is not None:
                call_id = existing_unnamed
            else:
                used_call_ids = (
                    set(existing_call_ids or ())
                    | set(tool_state_by_call)
                    | set(active_unnamed_calls_by_tool.values())
                )
                candidate_idx = len(used_call_ids)
                while f"tc_{candidate_idx}" in used_call_ids:
                    candidate_idx += 1
                call_id = f"tc_{candidate_idx}"
                if not is_terminal_state:
                    active_unnamed_calls_by_tool[tool_name] = call_id
            if is_terminal_state:
                active_unnamed_calls_by_tool.pop(tool_name, None)

        command_strs = _extract_event_command_strs(ev)
        command_str = command_strs[0] if command_strs else None
        raw_summary = ev.get("summary")
        if not (isinstance(raw_summary, str) and raw_summary.strip()):
            raw_summary = command_str or ev.get("path")
        incoming_summary = (
            raw_summary.strip()
            if isinstance(raw_summary, str) and raw_summary.strip()
            else None
        )
        has_meaningful_summary = incoming_summary is not None and incoming_summary != tool_name

        prev_state = tool_state_by_call.get(call_id) or pending_syntax_tools.get(call_id)
        effective_cmds = list(command_strs)
        if not effective_cmds and prev_state is not None:
            prev_cmds = prev_state.get("commands")
            if isinstance(prev_cmds, (list, tuple)):
                effective_cmds = [
                    c.strip() for c in prev_cmds if isinstance(c, str) and c.strip()
                ]
            if not effective_cmds:
                prev_cmd = prev_state.get("command_str")
                if isinstance(prev_cmd, str) and prev_cmd.strip():
                    effective_cmds = [prev_cmd.strip()]
        effective_cmd = effective_cmds[0] if effective_cmds else None
        category = _infer_tool_category(tool_name, command=effective_cmd)

        prev_summary = (
            str(prev_state["summary"])
            if prev_state is not None
            and isinstance(prev_state.get("summary"), str)
            and prev_state["summary"].strip()
            else None
        )
        prev_had_rich_summary = bool(prev_state and prev_state.get("has_rich_summary"))
        if has_meaningful_summary:
            assert incoming_summary is not None
            summary = incoming_summary
        elif command_str is None and prev_summary is not None and prev_had_rich_summary:
            summary = prev_summary
        else:
            summary = incoming_summary or tool_name

        if is_terminal_state:
            pending_syntax_tools.pop(call_id, None)
            tool_state_by_call.pop(call_id, None)

        allowed, block_reason, syntax_deferred = self._gate_mid_turn_tool_with_status(
            bot_id=bot_id,
            turn_id=turn_id,
            lane=lane,
            tool_name=tool_name,
            category=category,
            summary=summary,
            command=effective_cmd,
            commands=effective_cmds,
            allow_incomplete_syntax=not is_terminal_state,
        )
        meta: dict[str, Any] = {
            "call_id": call_id,
            "tool_name": tool_name,
            "category": category,
            "summary": summary,
            "raw_state": raw_state,
        }
        if not allowed:
            return False, block_reason, meta

        if not is_terminal_state:
            state_record = {
                "call_id": call_id,
                "tool_name": tool_name,
                "category": category,
                "summary": summary,
                "has_rich_summary": (
                    has_meaningful_summary
                    or (command_str is None and prev_had_rich_summary)
                ),
                "command_str": effective_cmd,
                "commands": effective_cmds,
            }
            tool_state_by_call[call_id] = state_record
            if syntax_deferred:
                pending_syntax_tools[call_id] = state_record
            else:
                pending_syntax_tools.pop(call_id, None)

        return True, None, meta

    def finalize_agy_stream_pending_tools(
        self,
        *,
        bot_id: str,
        turn_id: str,
        lane: Lane = Lane.GENERAL,
        pending_syntax_tools: dict[str, dict[str, Any]],
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Re-check any syntax-deferred ACTIVE tool calls strictly at stream end."""
        for pending in list(pending_syntax_tools.values()):
            p_cmd = pending.get("command_str")
            p_cmds = pending.get("commands")
            p_allowed, p_reason, _ = self._gate_mid_turn_tool_with_status(
                bot_id=bot_id,
                turn_id=turn_id,
                lane=lane,
                tool_name=str(pending["tool_name"]),
                category=str(pending["category"]),
                summary=str(pending["summary"]),
                command=str(p_cmd) if isinstance(p_cmd, str) else None,
                commands=(
                    [c for c in p_cmds if isinstance(c, str)]
                    if isinstance(p_cmds, (list, tuple))
                    else None
                ),
                allow_incomplete_syntax=False,
            )
            if not p_allowed:
                pending_syntax_tools.clear()
                return False, p_reason, pending
        pending_syntax_tools.clear()
        return True, None, None

    async def _execute_agy_engine(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        turn_id: str,
        message_id: str,
        prompt: str,
        model_id: str,
        allow_hydrogen: bool,
        use_browser_context: bool,
        is_channel: bool,
        lane: Lane = Lane.GENERAL,
        airlock_provenance: AirlockProvenance | None = None,
        airlock_sanitize: Callable[[str], str] | None = None,
        blocked_ids: Sequence[str] = (),
    ) -> str:
        bot_id = str(bot["id"])
        conv_id: str | None = None if is_channel else bot.get("conversation_id")

        if not self._is_app_enabled("app_agy"):
            disabled_msg = "Antigravity CLI (`agy`) is disabled in Connected Apps."
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=disabled_msg,
                tool_calls=[],
                conversation_id=conv_id,
                status="error",
            )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="agy app disabled",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        project_dir: Path | None = None
        proj_name = bot.get("project_name")
        if isinstance(proj_name, str) and proj_name.strip():
            with contextlib.suppress(ValueError):
                project_dir = resolve_project_dir(default_projects_root(), proj_name)

        browser_ctx: dict[str, Any] | None = None
        if (
            use_browser_context
            and self._is_app_enabled("app_playwright")
            and self._live_browser.running
        ):
            browser_ctx = await self._live_browser.extract_page_context()
            if browser_ctx is not None and (lane == Lane.MIXED or airlock_sanitize is not None):
                effective_sanitize: Callable[[str], str] = airlock_sanitize or (
                    lambda txt: self._sanitize_text_via_airlock(
                        txt,
                        blocked_ids=blocked_ids,
                        task_id=turn_id,
                    )
                )
                browser_ctx = self._sanitize_browser_context_via_airlock(
                    browser_ctx,
                    effective_sanitize,
                    blocked_ids=blocked_ids,
                    task_id=turn_id,
                )

        self._emit_presence(
            bot_id,
            state="working",
            subtext="Working on request...",
            computer_active=browser_ctx is not None,
            thread_id=thread_id,
            turn_id=turn_id,
        )

        chunks: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_index_map: dict[str, int] = {}
        final_status = "done"

        if find_agy_executable() is None:
            fallback_msg = (
                "Antigravity CLI (`agy`) is not installed on this host. "
                "Switch this bot's engine to `controlbot_runtime` or install `agy`."
            )
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=fallback_msg,
                tool_calls=[],
                conversation_id=conv_id,
                status="error",
            )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="agy CLI unavailable",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        gen = stream_agy_prompt(
            prompt=prompt,
            conversation_id=conv_id,
            project_dir=project_dir,
            model=model_id,
            allow_hydrogen=allow_hydrogen,
            browser_context=browser_ctx,
        )

        policy_blocked_reason: str | None = None
        pending_syntax_tools: dict[str, dict[str, Any]] = {}
        tool_state_by_call: dict[str, dict[str, Any]] = {}
        active_unnamed_calls_by_tool: dict[str, str] = {}
        next_unnamed_idx = 0
        try:
            async for ev in gen:
                ev_type = str(ev.get("type", ""))
                if ev_type == "init":
                    new_cid = str(ev.get("conversation_id") or "").strip()
                    if new_cid:
                        conv_id = new_cid
                        if not is_channel:
                            with contextlib.suppress(StoreNotFoundError):
                                self._store.update_bot(bot_id, {"conversation_id": conv_id})
                elif ev_type == "tool":
                    tool_name = str(ev.get("tool_name") or ev.get("name") or "tool")
                    raw_state = str(ev.get("state") or ev.get("status") or "ACTIVE").upper()
                    is_terminal_state = raw_state in {
                        "DONE",
                        "COMPLETED",
                        "SUCCESS",
                        "ERROR",
                        "FAILED",
                    }
                    raw_step_idx = ev.get("step_index")
                    parsed_step_idx: int | None = None
                    if isinstance(raw_step_idx, int) and not isinstance(raw_step_idx, bool):
                        parsed_step_idx = raw_step_idx
                    elif isinstance(raw_step_idx, str) and raw_step_idx.strip():
                        with contextlib.suppress(ValueError):
                            parsed_step_idx = int(raw_step_idx.strip())

                    if parsed_step_idx is not None:
                        call_id = f"tc_{parsed_step_idx}"
                    else:
                        existing_unnamed = active_unnamed_calls_by_tool.get(tool_name)
                        if existing_unnamed is not None:
                            call_id = existing_unnamed
                        else:
                            used_call_ids = (
                                set(tool_index_map)
                                | set(tool_state_by_call)
                                | set(active_unnamed_calls_by_tool.values())
                            )
                            candidate_idx = max(next_unnamed_idx, len(tool_calls))
                            while f"tc_{candidate_idx}" in used_call_ids:
                                candidate_idx += 1
                            next_unnamed_idx = candidate_idx + 1
                            call_id = f"tc_{candidate_idx}"
                            if not is_terminal_state:
                                active_unnamed_calls_by_tool[tool_name] = call_id
                        if is_terminal_state:
                            active_unnamed_calls_by_tool.pop(tool_name, None)

                    raw_summary = ev.get("summary")
                    incoming_summary = (
                        raw_summary.strip()
                        if isinstance(raw_summary, str) and raw_summary.strip()
                        else None
                    )
                    has_meaningful_summary = (
                        incoming_summary is not None and incoming_summary != tool_name
                    )
                    command_strs = _extract_event_command_strs(ev)
                    command_str = command_strs[0] if command_strs else None

                    prev_state = tool_state_by_call.get(call_id) or pending_syntax_tools.get(
                        call_id
                    )
                    effective_cmds = list(command_strs)
                    if not effective_cmds and prev_state is not None:
                        prev_cmds = prev_state.get("commands")
                        if isinstance(prev_cmds, (list, tuple)):
                            effective_cmds = [
                                c.strip() for c in prev_cmds if isinstance(c, str) and c.strip()
                            ]
                        if not effective_cmds:
                            prev_cmd = prev_state.get("command_str")
                            if isinstance(prev_cmd, str) and prev_cmd.strip():
                                effective_cmds = [prev_cmd.strip()]
                    effective_cmd = effective_cmds[0] if effective_cmds else None
                    category = _infer_tool_category(tool_name, command=effective_cmd)

                    prev_summary = (
                        str(prev_state["summary"])
                        if prev_state is not None
                        and isinstance(prev_state.get("summary"), str)
                        and prev_state["summary"].strip()
                        else None
                    )
                    prev_had_rich_summary = bool(prev_state and prev_state.get("has_rich_summary"))
                    if has_meaningful_summary:
                        assert incoming_summary is not None
                        summary = incoming_summary
                    elif command_str is None and prev_summary is not None and prev_had_rich_summary:
                        summary = prev_summary
                    else:
                        summary = incoming_summary or tool_name

                    if is_terminal_state:
                        pending_syntax_tools.pop(call_id, None)
                        tool_state_by_call.pop(call_id, None)

                    allowed, block_reason, syntax_deferred = self._gate_mid_turn_tool_with_status(
                        bot_id=bot_id,
                        turn_id=turn_id,
                        lane=lane,
                        tool_name=tool_name,
                        category=category,
                        summary=summary,
                        command=effective_cmd,
                        commands=effective_cmds,
                        allow_incomplete_syntax=not is_terminal_state,
                    )
                    if not allowed:
                        entry = {
                            "call_id": call_id,
                            "tool_name": tool_name,
                            "category": category,
                            "status": "error",
                            "summary": summary,
                            "output_preview": block_reason or "Blocked by PolicyGateway",
                        }
                        if call_id in tool_index_map:
                            tool_calls[tool_index_map[call_id]] = entry
                        else:
                            tool_index_map[call_id] = len(tool_calls)
                            tool_calls.append(entry)
                        self._event_bus.publish(
                            "tool.call.updated",
                            {"message_id": message_id, **entry},
                            bot_id=bot_id,
                            thread_id=thread_id,
                            turn_id=turn_id,
                        )
                        policy_blocked_reason = block_reason
                        final_status = "error"
                        break
                    if not is_terminal_state:
                        state_record = {
                            "call_id": call_id,
                            "tool_name": tool_name,
                            "category": category,
                            "summary": summary,
                            "has_rich_summary": (
                                has_meaningful_summary
                                or (command_str is None and prev_had_rich_summary)
                            ),
                            "command_str": effective_cmd,
                            "commands": effective_cmds,
                        }
                        tool_state_by_call[call_id] = state_record
                        if syntax_deferred:
                            pending_syntax_tools[call_id] = state_record
                        else:
                            pending_syntax_tools.pop(call_id, None)

                    call_status = (
                        "error"
                        if raw_state in {"ERROR", "FAILED"}
                        else ("ok" if raw_state in {"DONE", "COMPLETED", "SUCCESS"} else "running")
                    )
                    entry = {
                        "call_id": call_id,
                        "tool_name": tool_name,
                        "category": category,
                        "status": call_status,
                        "summary": summary,
                        "output_preview": "",
                    }
                    if call_id in tool_index_map:
                        tool_calls[tool_index_map[call_id]] = entry
                    else:
                        tool_index_map[call_id] = len(tool_calls)
                        tool_calls.append(entry)

                    self._event_bus.publish(
                        "tool.call.updated",
                        {"message_id": message_id, **entry},
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
                    self._emit_presence(
                        bot_id,
                        state="working",
                        subtext=summary[:120],
                        computer_active=category == "browser" or browser_ctx is not None,
                        step_label=summary[:120],
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
                elif ev_type == "delta":
                    delta = str(ev.get("text") or "")
                    if delta:
                        chunks.append(delta)
                        self._event_bus.publish(
                            "message.delta",
                            {"message_id": message_id, "text_delta": delta},
                            bot_id=bot_id,
                            thread_id=thread_id,
                            turn_id=turn_id,
                        )
                elif ev_type == "done":
                    done_cid = str(ev.get("conversation_id") or "").strip()
                    if done_cid:
                        conv_id = done_cid
                        if not is_channel:
                            with contextlib.suppress(StoreNotFoundError):
                                self._store.update_bot(bot_id, {"conversation_id": conv_id})
                    resp = str(ev.get("response") or "")
                    if resp and not chunks:
                        chunks.append(resp)
                        self._event_bus.publish(
                            "message.delta",
                            {"message_id": message_id, "text_delta": resp},
                            bot_id=bot_id,
                            thread_id=thread_id,
                            turn_id=turn_id,
                        )
                    for tc in tool_calls:
                        if tc["status"] == "running":
                            tc["status"] = "ok"
                elif ev_type == "error":
                    err_text = str(ev.get("message") or "Unknown engine error")
                    if not chunks:
                        chunks.append(f"Engine error: {err_text}")
                    final_status = "error"
        finally:
            await gen.aclose()

        if not policy_blocked_reason and pending_syntax_tools:
            for pending in list(pending_syntax_tools.values()):
                p_cmd = pending.get("command_str")
                p_cmds = pending.get("commands")
                p_allowed, p_reason, _ = self._gate_mid_turn_tool_with_status(
                    bot_id=bot_id,
                    turn_id=turn_id,
                    lane=lane,
                    tool_name=str(pending["tool_name"]),
                    category=str(pending["category"]),
                    summary=str(pending["summary"]),
                    command=str(p_cmd) if isinstance(p_cmd, str) else None,
                    commands=(
                        [c for c in p_cmds if isinstance(c, str)]
                        if isinstance(p_cmds, (list, tuple))
                        else None
                    ),
                    allow_incomplete_syntax=False,
                )
                if not p_allowed:
                    p_call_id = str(pending["call_id"])
                    entry = {
                        "call_id": p_call_id,
                        "tool_name": str(pending["tool_name"]),
                        "category": str(pending["category"]),
                        "status": "error",
                        "summary": str(pending["summary"]),
                        "output_preview": p_reason or "Blocked by PolicyGateway",
                    }
                    if p_call_id in tool_index_map:
                        tool_calls[tool_index_map[p_call_id]] = entry
                    else:
                        tool_index_map[p_call_id] = len(tool_calls)
                        tool_calls.append(entry)
                    self._event_bus.publish(
                        "tool.call.updated",
                        {"message_id": message_id, **entry},
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )
                    policy_blocked_reason = p_reason
                    final_status = "error"
                    break
            pending_syntax_tools.clear()

        if policy_blocked_reason:
            chunks.append(f"\n\n[Policy Block] {policy_blocked_reason}")

        final_content = "".join(chunks).strip()
        meta = VerifiedResponseMeta(
            verdict=VerdictState.CONTRADICTED if policy_blocked_reason else VerdictState.VERIFIED,
            lane=lane,
            domain_profile="mixed_industrial_web" if lane == Lane.MIXED else "general_office",
            degraded_banner=policy_blocked_reason,
            airlock_provenance=airlock_provenance,
        ).model_dump(mode="json")

        self._finalize_pages_and_message(
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
            message_id=message_id,
            content=final_content,
            tool_calls=tool_calls,
            conversation_id=conv_id,
            status=final_status,
            metadata=meta,
        )
        self._emit_presence(
            bot_id,
            state="idle" if final_status == "done" else "error",
            subtext="Nothing is blocked" if final_status == "done" else "Last turn had an error",
            computer_active=False,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        return final_content

    async def _await_runtime_run(
        self,
        run_id: str,
        *,
        bot_id: str,
        thread_id: str,
        turn_id: str,
        message_id: str | None,
        seen_receipts: set[str],
        tool_calls: list[dict[str, Any]],
        timeout_s: float = 180.0,
    ) -> TaskSnapshot | None:
        """Await runtime run completion using wait_for_run + bounded exponential backoff."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        last_progress_sig: tuple[float, str, int] | None = None

        wait_for_run_fn = getattr(self._coordinator, "wait_for_run", None)
        wait_task: asyncio.Task[Any] | None = None
        if callable(wait_for_run_fn):
            wait_task = asyncio.create_task(wait_for_run_fn(run_id, timeout=timeout_s))

        is_stub = type(self._coordinator).__name__ == "InMemoryCoordinatorStub"
        backoff = 0.1 if wait_task is not None else 0.05

        def _publish_snapshot_updates(snapshot: TaskSnapshot) -> None:
            nonlocal last_progress_sig
            for receipt in snapshot.receipts:
                if receipt.receipt_id in seen_receipts:
                    continue
                seen_receipts.add(receipt.receipt_id)
                tc_entry = {
                    "call_id": receipt.receipt_id,
                    "tool_name": receipt.tool_id,
                    "category": _infer_tool_category(receipt.tool_id),
                    "status": ("ok" if receipt.outcome.value in {"succeeded", "ok"} else "error"),
                    "summary": f"{receipt.tool_id} ({receipt.duration_ms:.0f}ms)",
                    "output_preview": str(receipt.error_detail or receipt.outcome.value)[:200],
                }
                tool_calls.append(tc_entry)
                if message_id is not None:
                    self._event_bus.publish(
                        "tool.call.updated",
                        {"message_id": message_id, **tc_entry},
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )

            sig = (
                float(snapshot.run.progress),
                str(snapshot.run.transition_reason),
                len(snapshot.transitions),
            )
            if sig != last_progress_sig:
                last_progress_sig = sig
                pct = int(snapshot.run.progress * 100)
                reason = str(snapshot.run.transition_reason)
                self._emit_presence(
                    bot_id,
                    state="working",
                    subtext=f"{reason} ({pct}%)",
                    computer_active=False,
                    step_label=reason,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                if message_id is not None:
                    self._event_bus.publish(
                        "thinking.delta",
                        {
                            "message_id": message_id,
                            "text_delta": f"{reason} ({pct}%)\n",
                        },
                        bot_id=bot_id,
                        thread_id=thread_id,
                        turn_id=turn_id,
                    )

        try:
            while True:
                snapshot = await maybe_await(self._coordinator.get_task_snapshot(run_id))
                if snapshot is None:
                    return None
                _publish_snapshot_updates(snapshot)

                if snapshot.run.status in TERMINAL_TASK_STATUSES | {TaskStatus.WAITING_FOR_INPUT}:
                    return snapshot

                if is_stub and wait_task is None:
                    return snapshot

                remaining = deadline - loop.time()
                if remaining <= 0:
                    return snapshot

                if wait_task is not None:
                    if wait_task.done():
                        # Final snapshot refresh after wait_task settled
                        final_snap = await maybe_await(self._coordinator.get_task_snapshot(run_id))
                        if final_snap is not None:
                            _publish_snapshot_updates(final_snap)
                        return final_snap
                    await asyncio.wait({wait_task}, timeout=min(backoff, remaining))
                else:
                    await asyncio.sleep(min(backoff, remaining))

                backoff = min(2.0, backoff * 1.5)
        except asyncio.CancelledError:
            with contextlib.suppress(KeyError, InvalidStateTransitionError, Exception):
                await maybe_await(self._coordinator.cancel_task(run_id, reason="turn_cancelled"))
            raise
        finally:
            if wait_task is not None:
                if not wait_task.done():
                    wait_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await wait_task

    def _runtime_backend_kind(
        self,
    ) -> Literal["local_http", "emulated_industrial", "stub_or_test"]:
        inner = getattr(self._coordinator, "_coordinator", None)
        if inner is None:
            inner = getattr(self._coordinator, "coordinator", None)
        model_client = getattr(inner, "_model_client", None)
        if type(model_client).__name__ == "LocalHttpModelClient":
            return "local_http"
        if inner is not None and getattr(model_client, "_turn_factory", None) is not None:
            return "emulated_industrial"
        return "stub_or_test"

    @staticmethod
    def _build_runtime_meta(snapshot: TaskSnapshot, *, lane: Lane) -> dict[str, Any]:
        result = snapshot.result
        verdict = VerdictState.VERIFIED
        agreements: list[str] = []
        partial: list[str] = []
        contradictions = result.contradictions if result is not None else ()

        if snapshot.run.status == TaskStatus.WAITING_FOR_INPUT:
            verdict = VerdictState.NEEDS_CLARIFICATION
        elif contradictions:
            verdict = VerdictState.CONTRADICTED
        elif snapshot.run.status == TaskStatus.PARTIAL:
            verdict = VerdictState.PARTIAL_EVIDENCE
        elif snapshot.run.status == TaskStatus.FAILED:
            verdict = VerdictState.CONTRADICTED

        if result is not None:
            if result.partial_info:
                partial.extend(_format_partial_info_summary(result.partial_info))
            for obs in result.verified_observations:
                if obs.authorized_evidence:
                    agreements.append(
                        f"{obs.source}:{obs.observed_label}={obs.value} {obs.unit or ''}".strip()
                    )

        domain_profile = (
            "industrial_ot"
            if lane == Lane.INDUSTRIAL
            else ("mixed_industrial_web" if lane == Lane.MIXED else "general_office")
        )
        return VerifiedResponseMeta(
            verdict=verdict,
            lane=lane,
            domain_profile=domain_profile,
            agreements=tuple(agreements),
            contradictions=contradictions,
            partial_evidence=tuple(partial),
        ).model_dump(mode="json")

    async def _execute_runtime_engine(
        self,
        *,
        bot: dict[str, Any],
        thread_id: str,
        turn_id: str,
        message_id: str,
        prompt: str,
        lane: Lane = Lane.INDUSTRIAL,
        user_message: dict[str, Any] | None = None,
        resolved_model: str | None = None,
        resolved_thinking: str | None = None,
        skill_ids: list[str] | None = None,
        handoff_context: str | None = None,
        page_context_id: str | None = None,
        allow_hydrogen: bool = False,
        use_browser: bool = False,
        is_channel: bool = False,
        facility_id: str | None = None,
        allowed_areas: Sequence[str] | None = None,
    ) -> str:
        bot_id = str(bot["id"])
        if not self._is_app_enabled("app_runtime"):
            disabled_msg = (
                "ControlBot Runtime app is disabled in Connected Apps. "
                "Please enable it in Settings -> Connected Apps or switch this bot's engine."
            )
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=disabled_msg,
                tool_calls=[],
                conversation_id=None,
                status="error",
            )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="Runtime app disabled",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        backend_kind = self._runtime_backend_kind()
        if lane == Lane.GENERAL and backend_kind == "emulated_industrial":
            if self._is_app_enabled("app_agy") and find_agy_executable() is not None:
                settings = self._store.get_settings()
                effective_user_msg = (
                    user_message if user_message is not None else {"content": prompt}
                )
                effective_thinking = resolved_thinking or str(
                    bot.get("thinking_level") or "medium"
                )
                effective_prompt = self._build_bot_prompt(
                    bot=bot,
                    thread_id=thread_id,
                    user_message=effective_user_msg,
                    skill_ids=skill_ids or [],
                    thinking_level=effective_thinking,
                    handoff_context=handoff_context,
                    page_context_id=page_context_id,
                )
                effective_model = resolved_model or str(
                    bot.get("model_id")
                    or settings.get("default_model_id")
                    or "gemini-4-carbon-low"
                )
                return await self._execute_agy_engine(
                    bot=bot,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    message_id=message_id,
                    prompt=effective_prompt,
                    model_id=effective_model,
                    allow_hydrogen=allow_hydrogen,
                    use_browser_context=use_browser,
                    is_channel=is_channel,
                    lane=Lane.GENERAL,
                )

            unavailable_msg = (
                "General chat cannot run on the industrial-only emulated runtime because "
                "Antigravity CLI (`agy`) and a local LLM endpoint are unavailable. "
                "Please configure GROKBOT_LLM_BASE_URL, enable/install `agy`, or "
                "switch this bot's engine."
            )
            err_meta = VerifiedResponseMeta(
                verdict=VerdictState.CONTRADICTED,
                lane=Lane.GENERAL,
                domain_profile="general_office",
                degraded_banner=unavailable_msg,
            ).model_dump(mode="json")
            self._event_bus.publish(
                "message.delta",
                {"message_id": message_id, "text_delta": unavailable_msg},
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            self._finalize_pages_and_message(
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                content=unavailable_msg,
                tool_calls=[],
                conversation_id=None,
                status="error",
                metadata=err_meta,
            )
            self._emit_presence(
                bot_id,
                state="error",
                subtext="General chat backend unavailable",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        self._emit_presence(
            bot_id,
            state="working",
            subtext="Submitting task to ControlBot Runtime...",
            computer_active=False,
            step_label="ControlBot Runtime",
            thread_id=thread_id,
            turn_id=turn_id,
        )

        if lane == Lane.GENERAL and backend_kind == "local_http":
            task_spec = TaskSpec(
                task_id=f"task-{uuid.uuid4().hex[:12]}",
                user_id="operator",
                profile_id="default",
                scope=self._resolve_runtime_scope(
                    facility_id=facility_id,
                    allowed_areas=allowed_areas,
                    user_message=user_message,
                    allowed_tools=("__general_chat__",),
                ),
                query=prompt.strip() or "Inspect system status",
                backend_mode=BackendMode.LOCAL_HTTP,
                evidence_requirements=EvidenceRequirements(
                    min_sources=1,
                    require_source_timestamp=False,
                    require_quality_check=False,
                ),
            )
        else:
            task_spec = TaskSpec(
                task_id=f"task-{uuid.uuid4().hex[:12]}",
                user_id="operator",
                profile_id="default",
                scope=self._resolve_runtime_scope(
                    facility_id=facility_id,
                    allowed_areas=allowed_areas,
                    user_message=user_message,
                ),
                query=prompt.strip() or "Inspect system status",
            )
        run = await maybe_await(self._coordinator.submit_task(task_spec))
        self._active_runtime_runs[thread_id] = run.run_id

        tool_calls: list[dict[str, Any]] = [
            {
                "call_id": "tc_submit",
                "tool_name": "controlbot_runtime.submit_task",
                "category": "agent",
                "status": "ok",
                "summary": f"Submitted run {run.run_id}",
                "output_preview": f"status={run.status.value}",
            }
        ]
        self._event_bus.publish(
            "tool.call.updated",
            {"message_id": message_id, **tool_calls[0]},
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )

        seen_receipts: set[str] = set()
        try:
            snapshot = await self._await_runtime_run(
                run.run_id,
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                message_id=message_id,
                seen_receipts=seen_receipts,
                tool_calls=tool_calls,
            )
        finally:
            if self._active_runtime_runs.get(thread_id) == run.run_id:
                self._active_runtime_runs.pop(thread_id, None)

        if snapshot is not None and snapshot.run.status == TaskStatus.CANCELLED and (
            snapshot.run.transition_reason == "interrupted_by_operator"
            or self._active_turns.get(thread_id) != turn_id
        ):
            cur_msg = self._store.get_message(message_id)
            if cur_msg is not None and cur_msg.get("status") == "streaming":
                updated = self._store.update_message(message_id, {"status": "interrupted"})
                self._event_bus.publish(
                    "message.completed",
                    {"message_id": message_id, "message": updated},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
            self._emit_presence(
                bot_id,
                state="idle",
                subtext="Interrupted by operator",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            return ""

        final_answer = ""
        final_status = "done"
        is_waiting_human = False
        verified_meta: dict[str, Any] | None = None

        if snapshot is not None:
            verified_meta = self._build_runtime_meta(snapshot, lane=lane)
            if snapshot.run.status == TaskStatus.WAITING_FOR_INPUT:
                is_waiting_human = True
                appr = self._store.create_approval(
                    bot_id=bot_id,
                    thread_id=thread_id,
                    kind="standard",
                    title=str(snapshot.run.required_action or "Runtime input required")[:240],
                    target=f"run:{run.run_id}",
                    arguments={"run_id": run.run_id},
                    pending_context={
                        "run_id": run.run_id,
                        "bot_id": bot_id,
                        "thread_id": thread_id,
                        "seen_receipts": sorted(seen_receipts),
                    },
                )
                self._event_bus.publish(
                    "hitl.approval.requested",
                    {"approval": appr},
                    bot_id=bot_id,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                final_answer = (
                    f"Run `{run.run_id}` is waiting for operator input: "
                    f"{snapshot.run.required_action or 'approval required'}."
                )
            elif snapshot.run.status in TERMINAL_TASK_STATUSES:
                if snapshot.result is not None and snapshot.result.answer:
                    final_answer = snapshot.result.answer
                else:
                    final_answer = (
                        f"ControlBot Runtime run `{run.run_id}` finished with status "
                        f"`{snapshot.run.status.value}` ({snapshot.run.transition_reason})."
                    )
                if snapshot.run.status == TaskStatus.FAILED:
                    final_status = "error"
                    p_info = snapshot.result.partial_info if snapshot.result is not None else None
                    final_answer = _format_runtime_error_message(final_answer, p_info)

        if not final_answer:
            final_answer = (
                f"Submitted run `{run.run_id}` to ControlBot Runtime "
                f"(current status: `{run.status.value}`)."
            )

        self._event_bus.publish(
            "message.delta",
            {"message_id": message_id, "text_delta": final_answer},
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        self._finalize_pages_and_message(
            bot_id=bot_id,
            thread_id=thread_id,
            turn_id=turn_id,
            message_id=message_id,
            content=final_answer,
            tool_calls=tool_calls,
            conversation_id=None,
            status=final_status,
            metadata=verified_meta,
        )
        if is_waiting_human:
            self._emit_presence(
                bot_id,
                state="waiting_human",
                subtext=f"Waiting for approval: {snapshot.run.required_action or 'input required'}"[
                    :120
                ]
                if snapshot is not None
                else "Waiting for approval",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
                needs_attention=True,
            )
        else:
            self._emit_presence(
                bot_id,
                state="idle" if final_status == "done" else "error",
                subtext="Nothing is blocked" if final_status == "done" else "Runtime task failed",
                computer_active=False,
                thread_id=thread_id,
                turn_id=turn_id,
            )
        return final_answer

    # ------------------------------------------------------------------
    # Routine Execution
    # ------------------------------------------------------------------

    def _start_routine_task(
        self,
        *,
        routine: dict[str, Any],
        run: dict[str, Any],
        thread_id: str | None,
        skip_auto_review: bool = False,
    ) -> asyncio.Task[None]:
        routine_id = str(routine["id"])
        run_id = str(run["id"])
        routine_turn_id = f"rtn_{run_id}"
        task = asyncio.create_task(
            self._run_routine_bg(
                routine=routine,
                run=run,
                skip_auto_review=skip_auto_review,
            )
        )
        self._routine_tasks.add(task)
        self._routine_tasks_by_routine.setdefault(routine_id, set()).add(task)

        if thread_id:
            self._thread_routine_tasks.setdefault(thread_id, {})[(routine_id, run_id)] = task
            self._active_routine_runs[thread_id] = (routine_id, run_id)
            cur_task = self._active_tasks.get(thread_id)
            cur_turn = self._active_turns.get(thread_id) or ""
            if cur_task is None or cur_task.done() or cur_turn.startswith("rtn_"):
                self._active_tasks[thread_id] = task
                self._active_turns[thread_id] = routine_turn_id

        def _cleanup(done_task: asyncio.Task[None]) -> None:
            self._routine_tasks.discard(done_task)
            r_set = self._routine_tasks_by_routine.get(routine_id)
            if r_set is not None:
                r_set.discard(done_task)
                if not r_set:
                    self._routine_tasks_by_routine.pop(routine_id, None)
            if not thread_id:
                return
            thread_rtns = self._thread_routine_tasks.get(thread_id)
            if thread_rtns is not None:
                if thread_rtns.get((routine_id, run_id)) is done_task:
                    thread_rtns.pop((routine_id, run_id), None)
                if not thread_rtns:
                    self._thread_routine_tasks.pop(thread_id, None)
            if self._active_tasks.get(thread_id) is done_task:
                self._active_tasks.pop(thread_id, None)
            if self._active_turns.get(thread_id) == routine_turn_id:
                self._active_turns.pop(thread_id, None)
            if self._active_routine_runs.get(thread_id) == (routine_id, run_id):
                self._active_routine_runs.pop(thread_id, None)

        task.add_done_callback(_cleanup)
        return task

    async def execute_routine(
        self,
        routine_id: str,
        *,
        trigger: str = "manual",
    ) -> dict[str, Any]:
        """Start an async routine run, emit status events, and return the initial RoutineRun."""
        routine = self._store.get_routine(routine_id)
        if routine is None:
            raise StoreNotFoundError(f"Routine not found: {routine_id}")
        bot_id = str(routine["bot_id"])
        bot = self._store.get_bot(bot_id)
        thread_id = str(bot["thread_id"]) if bot is not None else None
        run = self._store.create_routine_run(routine_id, bot_id, trigger=trigger)
        self._event_bus.publish(
            "routine.run.status",
            {"routine_id": routine_id, "run": run},
            bot_id=bot_id,
        )

        if trigger == "webhook" and not self._is_app_enabled("app_webhooks"):
            failed = self._store.update_routine_run(
                str(run["id"]),
                {
                    "status": "failed",
                    "error": "Routine Webhooks app is disabled in Connected Apps.",
                    "finished_at": utc_iso_now(),
                },
            )
            self._event_bus.publish(
                "routine.run.status",
                {"routine_id": routine_id, "run": failed},
                bot_id=bot_id,
            )
            return failed

        self._start_routine_task(routine=routine, run=run, thread_id=thread_id)
        return run

    async def _run_routine_bg(
        self,
        *,
        routine: dict[str, Any],
        run: dict[str, Any],
        skip_auto_review: bool = False,
    ) -> None:
        if self._stopping:
            return
        try:
            await self._execute_routine_bg(
                routine=routine,
                run=run,
                skip_auto_review=skip_auto_review,
            )
        except sqlite3.ProgrammingError as exc:
            if self._stopping and "closed database" in str(exc).lower():
                return
            raise

    async def _execute_routine_bg(
        self,
        *,
        routine: dict[str, Any],
        run: dict[str, Any],
        skip_auto_review: bool = False,
    ) -> None:
        routine_id = str(routine["id"])
        run_id = str(run["id"])
        bot_id = str(routine["bot_id"])
        bot = self._store.get_bot(bot_id)
        if bot is None:
            if self._store.get_routine(routine_id) is None:
                return
            with contextlib.suppress(StoreNotFoundError):
                failed = self._store.update_routine_run(
                    run_id,
                    {
                        "status": "failed",
                        "error": f"Bot {bot_id} no longer exists.",
                        "finished_at": utc_iso_now(),
                    },
                )
                self._event_bus.publish(
                    "routine.run.status",
                    {"routine_id": routine_id, "run": failed},
                    bot_id=bot_id,
                )
            return

        thread_id = str(bot["thread_id"])
        instruction = str(routine["instruction"]).strip()

        # Hard safety_floor check before anything executes
        floor_violation = safety_floor("routine.prompt", {"prompt": instruction})
        if floor_violation is not None:
            self._policy_gateway.evaluate_and_record(
                PolicyRequest(
                    actor_id=bot_id,
                    actor_role="bot",
                    lane=Lane.GENERAL,
                    tool_id="routine.prompt",
                    action_kind="write",
                    arguments={"prompt": instruction},
                    task_id=run_id,
                )
            )
            if self._store.get_routine(routine_id) is None:
                return
            finished_at = utc_iso_now()
            try:
                self._store.update_routine(routine_id, {"last_run_at": finished_at})
                failed = self._store.update_routine_run(
                    run_id,
                    {
                        "status": "failed",
                        "error": f"Action blocked by safety floor: `{floor_violation}`.",
                        "finished_at": finished_at,
                    },
                )
            except StoreNotFoundError:
                return
            self._event_bus.publish(
                "routine.run.status",
                {"routine_id": routine_id, "run": failed},
                bot_id=bot_id,
                thread_id=thread_id,
            )
            self._reset_routine_presence_idle(bot_id, thread_id, subtext="Blocked by safety floor")
            return

        # Auto-review ask_first check before invoking engines
        if not skip_auto_review:
            rules = self._store.list_auto_review_rules()
            matched_rule = _match_ask_first_rule(instruction, rules)
            if matched_rule is not None:
                if self._store.get_routine(routine_id) is None:
                    return
                try:
                    waiting_run = self._store.update_routine_run(
                        run_id,
                        {
                            "status": "waiting_approval",
                            "summary": f"Waiting for approval: {matched_rule[:120]}",
                        },
                    )
                except StoreNotFoundError:
                    return
                appr = self._store.create_approval(
                    bot_id=bot_id,
                    thread_id=thread_id,
                    kind="ask_first",
                    title=f"Confirm routine: {matched_rule[:120]}",
                    target=f"routine:{routine_id}",
                    risk_banner="This can't be undone",
                    arguments={
                        "routine_id": routine_id,
                        "routine_run_id": run_id,
                        "prompt": instruction[:500],
                        "matched_rule": matched_rule,
                    },
                    allow_always_allowed=True,
                    expires_in_minutes=30,
                    pending_context={
                        "routine_id": routine_id,
                        "routine_run_id": run_id,
                        "bot_id": bot_id,
                        "thread_id": thread_id,
                        "trigger": str(run.get("trigger") or "manual"),
                        "skip_auto_review": True,
                        "prompt": instruction,
                    },
                )
                self._event_bus.publish(
                    "routine.run.status",
                    {"routine_id": routine_id, "run": waiting_run},
                    bot_id=bot_id,
                    thread_id=thread_id,
                )
                self._emit_presence(
                    bot_id,
                    state="waiting_human",
                    subtext="Waiting for approval (Ask First)",
                    thread_id=thread_id,
                    needs_attention=True,
                )
                self._event_bus.publish(
                    "hitl.approval.requested",
                    {"approval": appr},
                    bot_id=bot_id,
                    thread_id=thread_id,
                )
                return

        summary = ""
        error_msg: str | None = None
        self._active_routine_runs.setdefault(thread_id, (routine_id, run_id))

        try:
            use_agy = str(bot.get("engine_id")) == "agy" and find_agy_executable() is not None
            if use_agy and not self._is_app_enabled("app_agy"):
                error_msg = "Antigravity CLI (`agy`) is disabled in Connected Apps."
            elif use_agy:
                project_dir: Path | None = None
                proj_name = bot.get("project_name")
                if isinstance(proj_name, str) and proj_name.strip():
                    with contextlib.suppress(ValueError):
                        project_dir = resolve_project_dir(default_projects_root(), proj_name)
                chunks: list[str] = []
                pending_syntax_tools: dict[str, dict[str, Any]] = {}
                tool_state_by_call: dict[str, dict[str, Any]] = {}
                active_unnamed_calls_by_tool: dict[str, str] = {}
                routine_turn_id = f"rtn_{run_id}"
                gen = stream_agy_prompt(
                    prompt=(
                        f"[SCHEDULED ROUTINE: {routine['name']}]\n"
                        f"{instruction}\n\n"
                        "If there are no notable findings, reply with an empty response or "
                        "NO_FINDINGS."
                    ),
                    project_dir=project_dir,
                    model=str(bot.get("model_id") or "gemini-4-carbon-low"),
                    timeout_s=90.0,
                )
                try:
                    async for ev in gen:
                        ev_type = str(ev.get("type") or "")
                        if ev_type == "tool":
                            allowed, block_reason, _ = self.gate_agy_stream_tool_event(
                                ev=ev,
                                bot_id=bot_id,
                                turn_id=routine_turn_id,
                                lane=Lane.GENERAL,
                                pending_syntax_tools=pending_syntax_tools,
                                tool_state_by_call=tool_state_by_call,
                                active_unnamed_calls_by_tool=active_unnamed_calls_by_tool,
                            )
                            if not allowed:
                                error_msg = block_reason or "Blocked by PolicyGateway"
                                break
                        elif ev_type == "delta":
                            chunks.append(str(ev.get("text") or ""))
                        elif ev_type == "done":
                            if pending_syntax_tools:
                                p_ok, p_reason, _ = self.finalize_agy_stream_pending_tools(
                                    bot_id=bot_id,
                                    turn_id=routine_turn_id,
                                    lane=Lane.GENERAL,
                                    pending_syntax_tools=pending_syntax_tools,
                                )
                                if not p_ok:
                                    error_msg = p_reason or "Blocked by PolicyGateway"
                                    break
                            if not chunks:
                                chunks.append(str(ev.get("response") or ""))
                        elif ev_type == "error":
                            error_msg = str(ev.get("message") or "Routine execution error")
                    if not error_msg and pending_syntax_tools:
                        p_ok, p_reason, _ = self.finalize_agy_stream_pending_tools(
                            bot_id=bot_id,
                            turn_id=routine_turn_id,
                            lane=Lane.GENERAL,
                            pending_syntax_tools=pending_syntax_tools,
                        )
                        if not p_ok:
                            error_msg = p_reason or "Blocked by PolicyGateway"
                finally:
                    await gen.aclose()
                summary = "".join(chunks).strip()
            else:
                if not self._is_app_enabled("app_runtime"):
                    error_msg = "ControlBot Runtime app is disabled in Connected Apps."
                else:
                    task_spec = TaskSpec(
                        task_id=f"rtn-{uuid.uuid4().hex[:10]}",
                        user_id="operator",
                        profile_id="default",
                        scope=self._resolve_runtime_scope(),
                        query=instruction or routine["name"],
                    )
                    coord_run = await maybe_await(self._coordinator.submit_task(task_spec))
                    self._active_runtime_runs[thread_id] = coord_run.run_id
                    self._active_routine_runs[thread_id] = (routine_id, run_id)
                    self._routine_coord_runs.setdefault(routine_id, set()).add(coord_run.run_id)
                    keep_coord_run = False
                    snap: TaskSnapshot | None = None
                    try:
                        snap = await self._await_runtime_run(
                            coord_run.run_id,
                            bot_id=bot_id,
                            thread_id=thread_id,
                            turn_id=f"rtn_{run_id}",
                            message_id=None,
                            seen_receipts=set(),
                            tool_calls=[],
                            timeout_s=90.0,
                        )
                        if (
                            snap is not None
                            and snap.run.status == TaskStatus.WAITING_FOR_INPUT
                            and self._store.get_routine(routine_id) is not None
                        ):
                            keep_coord_run = True
                    except asyncio.CancelledError:
                        with contextlib.suppress(Exception):
                            await maybe_await(
                                self._coordinator.cancel_task(
                                    coord_run.run_id, reason="interrupted_by_operator"
                                )
                            )
                        raise
                    finally:
                        if not keep_coord_run:
                            c_set = self._routine_coord_runs.get(routine_id)
                            if c_set is not None:
                                c_set.discard(coord_run.run_id)
                                if not c_set:
                                    self._routine_coord_runs.pop(routine_id, None)
                        if self._active_runtime_runs.get(thread_id) == coord_run.run_id:
                            self._active_runtime_runs.pop(thread_id, None)
                        if self._active_routine_runs.get(thread_id) == (routine_id, run_id):
                            self._active_routine_runs.pop(thread_id, None)
                    if snap is not None and snap.run.status == TaskStatus.WAITING_FOR_INPUT:
                        if self._store.get_routine(routine_id) is None:
                            with contextlib.suppress(Exception):
                                await maybe_await(
                                    self._coordinator.cancel_task(
                                        coord_run.run_id, reason="routine_deleted"
                                    )
                                )
                            return
                        try:
                            req_act = snap.run.required_action or "input required"
                            waiting_run = self._store.update_routine_run(
                                run_id,
                                {
                                    "status": "waiting_approval",
                                    "summary": (
                                        f"Routine **{routine['name']}** paused for operator input "
                                        f"(run `{coord_run.run_id}`): {req_act}."
                                    )[:1000],
                                },
                            )
                        except StoreNotFoundError:
                            return
                        appr = self._store.create_approval(
                            bot_id=bot_id,
                            thread_id=thread_id,
                            kind="standard",
                            title=str(snap.run.required_action or "Routine input required")[:240],
                            target=f"run:{coord_run.run_id}",
                            arguments={"run_id": coord_run.run_id},
                            pending_context={
                                "run_id": coord_run.run_id,
                                "bot_id": bot_id,
                                "thread_id": thread_id,
                                "routine_id": routine_id,
                                "routine_run_id": run_id,
                            },
                        )
                        self._event_bus.publish(
                            "hitl.approval.requested",
                            {"approval": appr},
                            bot_id=bot_id,
                            thread_id=thread_id,
                        )
                        self._event_bus.publish(
                            "routine.run.status",
                            {"routine_id": routine_id, "run": waiting_run},
                            bot_id=bot_id,
                            thread_id=thread_id,
                        )
                        self._emit_presence(
                            bot_id,
                            state="waiting_human",
                            subtext=f"Waiting for approval: {req_act}"[:120],
                            thread_id=thread_id,
                            needs_attention=True,
                        )
                        return
                    elif snap is not None and snap.run.status in {
                        TaskStatus.FAILED,
                        TaskStatus.CANCELLED,
                    }:
                        error_msg = (
                            snap.result.answer
                            if snap.result is not None and snap.result.answer
                            else (
                                f"Runtime routine run `{coord_run.run_id}` "
                                f"{snap.run.status.value} ({snap.run.transition_reason})."
                            )
                        )
                    elif snap is not None and snap.result is not None and snap.result.answer:
                        summary = snap.result.answer
                    else:
                        final_st = (snap.run.status if snap is not None else coord_run.status).value
                        summary = (
                            f"Routine **{routine['name']}** executed via runtime "
                            f"(run `{coord_run.run_id}`, status `{final_st}`)."
                        )
        except asyncio.CancelledError:
            if not self._stopping:
                self._fail_interrupted_routine_run(
                    routine_id,
                    run_id,
                    thread_id=thread_id,
                    error="Interrupted by operator.",
                )
                if self._active_turns.get(thread_id) == f"rtn_{run_id}":
                    self._reset_routine_presence_idle(
                        bot_id,
                        thread_id,
                        subtext="Interrupted by operator",
                    )
            raise
        except Exception as exc:  # noqa: BLE001
            if self._stopping:
                return
            error_msg = str(scrub_v1_payload(str(exc)))[:300]
        finally:
            if self._active_routine_runs.get(thread_id) == (routine_id, run_id):
                self._active_routine_runs.pop(thread_id, None)

        if self._stopping:
            return
        if self._store.get_routine(routine_id) is None:
            return
        cur_run = self._store.get_routine_run(run_id)
        if cur_run is not None and cur_run.get("status") in {"failed", "cancelled"}:
            return

        finished_at = utc_iso_now()
        try:
            self._store.update_routine(routine_id, {"last_run_at": finished_at})
        except StoreNotFoundError:
            return

        if error_msg:
            try:
                updated_run = self._store.update_routine_run(
                    run_id,
                    {"status": "failed", "error": error_msg, "finished_at": finished_at},
                )
            except StoreNotFoundError:
                return
            self._event_bus.publish(
                "routine.run.status",
                {"routine_id": routine_id, "run": updated_run},
                bot_id=bot_id,
                thread_id=thread_id,
            )
            self._reset_routine_presence_idle(bot_id, thread_id, subtext="Routine failed")
            return

        if self._store.get_routine(routine_id) is None:
            return

        message_id: str | None = None
        is_silent = not summary or summary.strip().upper() in {"NO_FINDINGS", "NONE", "SILENT"}
        if not is_silent:
            posted = self._store.create_message(
                thread_id=thread_id,
                sender_type="bot",
                sender_bot_id=bot_id,
                sender_name=str(bot["name"]),
                content=f"**Routine: {routine['name']}**\n\n{summary}",
                model_id=str(bot.get("model_id") or ""),
                status="done",
            )
            message_id = str(posted["id"])
            self._event_bus.publish(
                "message.completed",
                {"message_id": message_id, "message": posted},
                bot_id=bot_id,
                thread_id=thread_id,
            )

        try:
            updated_run = self._store.update_routine_run(
                run_id,
                {
                    "status": "succeeded",
                    "summary": summary[:1000],
                    "message_id": message_id,
                    "finished_at": finished_at,
                },
            )
        except StoreNotFoundError:
            return
        self._event_bus.publish(
            "routine.run.status",
            {"routine_id": routine_id, "run": updated_run},
            bot_id=bot_id,
            thread_id=thread_id,
        )
        self._reset_routine_presence_idle(bot_id, thread_id, subtext="Idle")
