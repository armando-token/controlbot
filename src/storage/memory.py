"""Compartmentalized SQLite FTS5 memory engine with SQL ACLs, TTL, and rev locks (CB-07)."""

from __future__ import annotations

import contextlib
import functools
import json
import os
import re
import sqlite3
import threading
import uuid
from bisect import bisect_right
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from src.contracts.redaction import is_sensitive_key
from src.storage.db import read_transaction, write_transaction
from src.storage.errors import ConflictError, NotFoundError, StorageError
from src.storage.redaction import is_sensitive_key_strict

MemoryScope = Literal["user", "agent_role", "thread", "project_area", "org_approved"]
MemoryKind = Literal["preference", "approved_procedure", "dated_observation", "source_reference"]

VALID_SCOPES: frozenset[str] = frozenset(
    {"user", "agent_role", "thread", "project_area", "org_approved"}
)
VALID_KINDS: frozenset[str] = frozenset(
    {"preference", "approved_procedure", "dated_observation", "source_reference"}
)

PINNED_MAX_LINES = 150
PINNED_MAX_BYTES = 16 * 1024
RECALL_MAX_MEMORY_ITEMS = 4
RECALL_MAX_THREAD_PASSAGES = 4
RECALL_MAX_CHARS = 6000

_FTS_TOKEN_RE = re.compile(r"[^\s.,;:!?()\[\]{}<>\"'`~@#$%^&*+=|\\]+")
_REDACTED_N_CHARS_RE = re.compile(r"redacted \d+ chars")
_PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_COMMA_SEMI_UNQUOTED = r"(?=$|\s|[\w-]+\s*[:=])"
_COMMA_SEMI_QUOTED = (
    r"(?=$|\s|[\w-]+\s*[:=]|\"(?:\\.|[^\"\\\r\n])+\"\s*:|'(?:\\.|[^'\\\r\n])+'\s*:)"
)
_COMMA_SEMI_UNQUOTED_RE = re.compile(_COMMA_SEMI_UNQUOTED)
_COMMA_SEMI_QUOTED_RE = re.compile(_COMMA_SEMI_QUOTED)
_AMP_TAIL_RE = re.compile(r"&(?=$|\s|[\w-]+\s*=)")
_VALID_TAIL_UNQUOTED_RE = re.compile(
    r"[)\]}]*(?:$|\s|[,;]" + _COMMA_SEMI_UNQUOTED + r"|&(?=$|\s|[\w-]+\s*=))"
)
_VALID_TAIL_ENCLOSED_QUOTE_RE = re.compile(
    r"[)\]}]*(?:$|\s|[,;]" + _COMMA_SEMI_QUOTED + r"|&(?=$|\s|[\w-]+\s*=))"
)
_VALID_TAIL_STOP_BRACKET_UNQUOTED_RE = re.compile(
    r"[)\]}]+(?:$|\s|[,;]" + _COMMA_SEMI_UNQUOTED + r"|&(?=$|\s|[\w-]+\s*=))"
)
_VALID_TAIL_STOP_BRACKET_QUOTED_RE = re.compile(
    r"[)\]}]+(?:$|\s|[,;]" + _COMMA_SEMI_QUOTED + r"|&(?=$|\s|[\w-]+\s*=))"
)
_VALID_STRUCTURED_TAIL_RE = re.compile(
    r"[)\]}]*(?:$|\s|[,;]" + _COMMA_SEMI_QUOTED + r"|&(?=$|\s|[\w-]+\s*=))"
)
_ALREADY_REDACTED_AUTH_STR_RE = re.compile(
    r"(?i)(?:Bearer|Basic)\s+(?:redacted\s+\d+\s+chars|(?P<q>\\*[\"'])redacted\s+\d+\s+chars(?P=q))"
)
_PROBE_REDACTED_AUTH_STR_RE = re.compile(
    r"(?i)(?:Bearer|Basic)\s+(?:\[REDACTED\]|(?P<q>\\*[\"'])\[REDACTED\](?P=q))"
)
_PROBE_TRAILING_BRACKET_RE = re.compile(
    r"\[REDACTED\](?=[)\]}]+(?:$|\s|[,;]" + _COMMA_SEMI_UNQUOTED + r"|&(?=$|\s|[\w-]+\s*=)))"
)
_REDACTED_AUTH_PUNCT_RE = re.compile(
    r"(?i)\b(Bearer|Basic)\s+\[REDACTED\](?=[\s,;:'\"\)\}\]]|$)"
)
_WORD_CHAR_RE = re.compile(r"\w")
_EQ_RE = re.compile(r"=")
_OPEN_BRACE_RE = re.compile(r"[\{\[]")
_QUOTE_EVENT_RE = re.compile(r'[\r\n"\']|\\+')
_QUERY_BRANCH3_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|secret_key|secretKey|secret-key|"
    r"api_key|api-key|apikey|x_api_key|x-api-key|xApiKey|token|"
    r"access_token|accessToken|refresh_token|refreshToken|auth_token|authToken|"
    r"session_token|sessionToken|csrf_token|csrfToken|id_token|idToken|"
    r"client_secret|clientSecret|private_key|privateKey|credential|credentials|"
    r"authorization|cookie|cookies|set_cookie|set-cookie|setCookie|bearer)\Z"
)
_QUERY_BRANCH1_SUFFIX_RE = re.compile(
    r"(?i)[_-](?:password|passwd|secret(?:[_-]?key)?|private[_-]?key|"
    r"api[_-]?key|apikey|token|cookies?|credentials?)\Z"
)
_QUERY_BRANCH2_SUFFIX_RE = re.compile(
    r"(?:Password|Passwd|Secret(?:Key)?|PrivateKey|ApiKey|Token|Cookies?|Credentials?)\Z"
)
_AUTH_PREFIX_STR_RE = re.compile(r"(?i)^(?:Bearer|Basic)\s+")
_JSON_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_URL_USERINFO_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)(?:([^/\s?#:@]+)(?::([^/\s?#@]*))?|:([^/\s?#@]+))@"
)
_COLON_EQ_RE = re.compile(r"[:=]")
_SENSITIVE_KEY_TAIL_RE = re.compile(
    r"(?i)(?:password|passwd|secret|key|token|cookies?|credentials?|authorization|bearer)\Z"
)
_KV_PREFIXED_END_RE = re.compile(
    r"(?i)[_-](?:password|passwd|secret(?:[_-]?key)?|private[_-]?key|"
    r"api[_-]?key|apikey|token|cookies?|credentials?)\Z"
)
_SENSITIVE_KEY_EXACT_RE = re.compile(
    r"(?i)(?:"
    r"(?-i:[a-z0-9][A-Za-z0-9]*(?:Password|Passwd|Secret(?:Key)?|PrivateKey|"
    r"ApiKey|Token|Cookies?|Credentials?))"
    r"|password|passwd|secret|secret_key|secretKey|secret-key|"
    r"api_key|api-key|apikey|x_api_key|x-api-key|xApiKey|token|"
    r"access_token|accessToken|refresh_token|refreshToken|auth_token|authToken|"
    r"session_token|sessionToken|csrf_token|csrfToken|id_token|idToken|"
    r"client_secret|clientSecret|private_key|privateKey|credential|credentials|"
    r"authorization|cookie|cookies|set_cookie|set-cookie|setCookie|bearer"
    r")\Z"
)
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(?P<scheme>Bearer|Basic)(?P<ws>\s+)")
_AUTH_COLON_PREFIX_RE = re.compile(r"(?i)\bAuthorization\s*:\s*\Z")
_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9_]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)


class MemoryError(StorageError):
    """Base error for memory engine failures."""


class MemoryValidationError(MemoryError, ValueError):
    """Raised when memory input or timestamps fail validation."""


class MemoryPermissionError(MemoryError, PermissionError):
    """Raised when ACL or approved_procedure role/provenance guards fail."""


class MemoryNotFoundError(MemoryError, NotFoundError):
    """Raised when a requested memory item does not exist."""


class MemoryConflictError(MemoryError, ConflictError):
    """Raised on optimistic revision lock mismatch."""


@dataclass(frozen=True, slots=True)
class MemoryAccessContext:
    """Caller identity and ACL attributes enforced in SQL WHERE clauses."""

    user_id: str | None = None
    agent_role: str | None = None
    thread_id: str | None = None
    project_area: str | None = None
    include_org_approved: bool = True
    actor_role: str = "Operator"


@dataclass(frozen=True, slots=True)
class MemoryContextBundle:
    """Structured prompt injection bundle with pinned and recalled sections."""

    pinned_text: str
    recall_text: str
    combined_text: str
    pinned_count: int
    recalled_count: int
    passage_count: int
    total_chars: int
    item_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pinned_text": self.pinned_text,
            "recall_text": self.recall_text,
            "combined_text": self.combined_text,
            "pinned_count": self.pinned_count,
            "recalled_count": self.recalled_count,
            "passage_count": self.passage_count,
            "total_chars": self.total_chars,
            "item_ids": list(self.item_ids),
        }


def utc_iso_now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_scope(scope: str) -> MemoryScope:
    """Normalize scope aliases ('project', 'project/area') into canonical MemoryScope."""
    cleaned = scope.strip().lower()
    if cleaned in {"project", "project/area"}:
        cleaned = "project_area"
    if cleaned not in VALID_SCOPES:
        raise MemoryValidationError(f"Unsupported memory scope: {scope!r}")
    return cleaned  # type: ignore[return-value]


def normalize_kind(kind: str) -> MemoryKind:
    cleaned = kind.strip().lower()
    if cleaned not in VALID_KINDS:
        raise MemoryValidationError(f"Unsupported memory kind: {kind!r}")
    return cleaned  # type: ignore[return-value]


def normalize_iso_timestamp(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        normalized = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MemoryValidationError(
            f"Invalid ISO-8601 timestamp for {field_name}: {value!r}"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_fts5_query(
    raw_query: str,
    *,
    operator: Literal["AND", "OR"] = "AND",
) -> str | None:
    """Build a safe double-quoted FTS5 query preventing '-' negation and operator injection."""
    tokens = _FTS_TOKEN_RE.findall(raw_query.strip())
    cleaned = [tok for tok in tokens if not all(ch in "-_/" for ch in tok)]
    if not cleaned:
        return None
    quoted = ['"' + tok.replace('"', '""') + '"' for tok in cleaned]
    return " ".join(quoted) if operator == "AND" else " OR ".join(quoted)


_RE_CI_FOLD_TRANS = str.maketrans(
    {"\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"}
)

_EXACT_SENSITIVE_KV_KEYS_CI: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_key",
        "secretkey",
        "secret-key",
        "api_key",
        "api-key",
        "apikey",
        "x_api_key",
        "x-api-key",
        "xapikey",
        "token",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "auth_token",
        "authtoken",
        "session_token",
        "sessiontoken",
        "csrf_token",
        "csrftoken",
        "id_token",
        "idtoken",
        "client_secret",
        "clientsecret",
        "private_key",
        "privatekey",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "cookies",
        "set_cookie",
        "set-cookie",
        "setcookie",
        "bearer",
    }
)

# Exact set of characters that can immediately precede '=' or ':' in any sensitive key.
_SENSITIVE_KEY_END_CHARS = frozenset("dDeElLnNrRsStTyY\u017f")


def _re_ci_fold(text: str) -> str:
    if text.isascii():
        return text
    return text.translate(_RE_CI_FOLD_TRANS)


def _is_already_redacted_placeholder(text: str) -> bool:
    s = text.strip()
    n = len(s)
    if n < 16 or s[0] != "r":
        return False
    if s.startswith("redacted ") and s.endswith(" chars"):
        num = s[9 : n - 6]
        if num.isascii():
            return num.isdigit()
        return bool(_REDACTED_N_CHARS_RE.fullmatch(s))
    return False


@functools.lru_cache(maxsize=4096)
def _is_sensitive_memory_kv_key(key: str) -> bool:
    if is_sensitive_key_strict(key):
        return True
    folded = _re_ci_fold(key)
    if folded != key and is_sensitive_key(folded):
        return True
    norm = folded.strip().lower()
    if norm in _EXACT_SENSITIVE_KV_KEYS_CI:
        return True
    norm_us = norm.replace("-", "_")
    if norm_us in _EXACT_SENSITIVE_KV_KEYS_CI:
        return True
    return norm_us.endswith(("_secretkey", "_privatekey"))


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_MAX_JSON_AST_DEPTH = 64
_MAX_NESTED_REDACT_DEPTH = 16

_JSON_SCALAR: Literal[0] = 0
_JSON_STR: Literal[1] = 1
_JSON_ARR: Literal[2] = 2
_JSON_OBJ: Literal[3] = 3

_JsonStr = tuple[Literal[1], int, int]
_JsonScalar = tuple[Literal[0], int, int]
_JsonArray = tuple[Literal[2], int, int, tuple[Any, ...]]
_JsonObject = tuple[Literal[3], int, int, tuple[tuple[tuple[Literal[1], int, int], Any], ...]]
_JsonNode = _JsonStr | _JsonScalar | _JsonArray | _JsonObject


@dataclass(slots=True)
class _KvMatch:
    anchor: int
    val_start: int
    raw_key: str
    sep: str
    key_bs: int
    match_end: int


def _count_leading_backslashes(text: str, pos: int) -> int:
    bs = 0
    idx = pos - 1
    while idx >= 0 and text[idx] == "\\":
        bs += 1
        idx -= 1
    return bs


def _is_valid_escape_bs(bs: int) -> bool:
    return bs >= 0 and (bs & (bs + 1)) == 0


def _find_line_end(text: str, start: int) -> int:
    idx = start
    n = len(text)
    while idx < n and text[idx] not in "\r\n":
        idx += 1
    return idx


def _match_quoted_span(
    text: str, start: int
) -> tuple[bool, int, int, int, str, str] | None:
    """Match a quoted or backslash-escaped-quoted span with bitwise backslash parity."""
    n = len(text)
    idx = start
    bs = 0
    while idx < n and text[idx] == "\\":
        bs += 1
        idx += 1
    if idx >= n or text[idx] not in "\"'":
        return None
    if not _is_valid_escape_bs(bs):
        return None
    qchar = text[idx]
    prefix = text[start : idx + 1]
    inner_start = idx + 1
    pos = inner_start
    mod = 2 * (bs + 1)
    while pos < n:
        ch = text[pos]
        if ch in "\r\n":
            return False, inner_start, pos, pos, prefix, qchar
        if ch == "\\":
            k = 0
            while pos + k < n and text[pos + k] == "\\":
                k += 1
            if pos + k < n and text[pos + k] == qchar:
                rem = k % mod
                if rem == bs:
                    inner_end = pos + k - bs
                    return True, inner_start, inner_end, pos + k + 1, prefix, qchar
                if rem == 2 * bs + 1:
                    pos += k + 1
                    continue
                line_end = _find_line_end(text, pos)
                return False, inner_start, line_end, line_end, prefix, qchar
            pos += k
            continue
        if ch == qchar:
            if bs == 0:
                return True, inner_start, pos, pos + 1, prefix, qchar
            line_end = _find_line_end(text, pos)
            return False, inner_start, line_end, line_end, prefix, qchar
        pos += 1
    return False, inner_start, n, n, prefix, qchar


def _find_balanced_container_end(
    text: str, start: int, *, cache: dict[int, int | None] | None = None
) -> int | None:
    """Find exclusive end index of balanced {...} or [...] tracking escape-parity strings."""
    if cache is not None and start in cache:
        return cache[start]
    n = len(text)
    if start >= n or text[start] not in "{[":
        return None
    stack: list[tuple[str, int]] = [("}" if text[start] == "{" else "]", start)]
    in_qchar: str | None = None
    in_bs = 0
    idx = start + 1

    def _fail() -> None:
        if cache is not None:
            for _, op in stack:
                cache[op] = None

    while idx < n:
        ch = text[idx]
        if in_qchar is not None:
            if ch in "\r\n":
                _fail()
                return None
            if ch == "\\":
                k = 0
                while idx + k < n and text[idx + k] == "\\":
                    k += 1
                if idx + k < n and text[idx + k] == in_qchar:
                    mod = 2 * (in_bs + 1)
                    rem = k % mod
                    if rem == in_bs:
                        in_qchar = None
                        idx += k + 1
                        continue
                    if rem == 2 * in_bs + 1:
                        idx += k + 1
                        continue
                    _fail()
                    return None
                idx += k
                continue
            if ch == in_qchar:
                if in_bs == 0:
                    in_qchar = None
                    idx += 1
                    continue
                _fail()
                return None
            idx += 1
            continue

        if ch == "\\":
            k = 0
            while idx + k < n and text[idx + k] == "\\":
                k += 1
            if idx + k < n and text[idx + k] in "\"'" and _is_valid_escape_bs(k):
                in_qchar = text[idx + k]
                in_bs = k
                idx += k + 1
                continue
            idx += k
            continue
        if ch in "\"'":
            in_qchar = ch
            in_bs = 0
            idx += 1
            continue
        if ch in "{[":
            if cache is not None and idx in cache:
                cached_end = cache[idx]
                if cached_end is None:
                    _fail()
                    return None
                idx = cached_end
                continue
            stack.append(("}" if ch == "{" else "]", idx))
        elif ch in "}]":
            if not stack or stack[-1][0] != ch:
                _fail()
                return None
            _, open_pos = stack.pop()
            if cache is not None:
                cache[open_pos] = idx + 1
            if not stack:
                return idx + 1
        idx += 1
    _fail()
    return None


def _build_json_bounds(
    text: str,
    max_depth: int = _MAX_JSON_AST_DEPTH,
    *,
    min_needed_end: int = 0,
) -> tuple[dict[int, int], list[int]]:
    """Build O(N) right-to-left span-end index of valid RFC 8259 JSON objects/arrays."""
    n = len(text)
    last_close_obj = text.rfind("}")
    last_close_arr = text.rfind("]")
    if last_close_obj == -1 and last_close_arr == -1:
        return {}, []

    last_close = max(last_close_obj, last_close_arr)
    positions = [m.start() for m in _OPEN_BRACE_RE.finditer(text, 0, last_close)]
    if not positions:
        return {}, []

    fast_str = "\\" not in text and text.isprintable()
    ws = " \t\r\n"

    def _skip_str_end(idx: int) -> int | None:
        if idx >= n or text[idx] != '"':
            return None
        q_end = text.find('"', idx + 1)
        if q_end != -1:
            if fast_str:
                return q_end + 1
            slice_str = text[idx + 1 : q_end]
            if "\\" not in slice_str and slice_str.isprintable():
                return q_end + 1
        pos = idx + 1
        while pos < n:
            ch = text[pos]
            if ord(ch) < 0x20:
                return None
            if ch == '"':
                return pos + 1
            if ch == "\\":
                pos += 1
                if pos >= n:
                    return None
                esc = text[pos]
                if esc in '"\\/bfnrt':
                    pos += 1
                elif esc == "u":
                    if pos + 5 > n:
                        return None
                    for hx in text[pos + 1 : pos + 5]:
                        if hx not in _HEX_DIGITS:
                            return None
                    pos += 5
                else:
                    return None
            else:
                pos += 1
        return None

    def _skip_scalar_or_str_end(idx: int) -> int | None:
        if idx >= n:
            return None
        ch = text[idx]
        if ch == '"':
            return _skip_str_end(idx)
        if "0" <= ch <= "9":
            if idx + 1 == n or text[idx + 1] in ",}] \t\r\n":
                return idx + 1
            num_m = _JSON_NUMBER_RE.match(text, idx)
            return num_m.end() if num_m is not None else None
        if ch == "-":
            num_m = _JSON_NUMBER_RE.match(text, idx)
            return num_m.end() if num_m is not None else None
        if text.startswith("true", idx) or text.startswith("null", idx):
            return idx + 4
        if text.startswith("false", idx):
            return idx + 5
        return None

    span_end: dict[int, int] = {}
    span_depth: dict[int, int] = {}
    needed: list[int] = []
    for start in reversed(positions):
        if text[start] == "{":
            cur = start + 1
            if cur < n and text[cur] in ws:
                cur += 1
                while cur < n and text[cur] in ws:
                    cur += 1
            if cur >= n:
                continue
            if text[cur] == "}":
                end_p = cur + 1
                span_end[start] = end_p
                span_depth[start] = 0
                if end_p > min_needed_end:
                    needed.append(start)
                continue
            if text[cur] != '"' or max_depth < 1:
                continue
            max_child_depth = 0
            while True:
                if cur < n and text[cur] == '"':
                    q_end = text.find('"', cur + 1)
                    if q_end != -1:
                        if fast_str:
                            cur = q_end + 1
                        else:
                            s_slice = text[cur + 1 : q_end]
                            if "\\" not in s_slice and s_slice.isprintable():
                                cur = q_end + 1
                            else:
                                next_c = _skip_str_end(cur)
                                if next_c is None:
                                    break
                                cur = next_c
                    else:
                        break
                else:
                    break
                if cur < n and text[cur] in ws:
                    cur += 1
                    while cur < n and text[cur] in ws:
                        cur += 1
                if cur >= n or text[cur] != ":":
                    break
                cur += 1
                if cur < n and text[cur] in ws:
                    cur += 1
                    while cur < n and text[cur] in ws:
                        cur += 1
                if cur >= n:
                    break
                ch_v = text[cur]
                if ch_v in "{[":
                    c_end = span_end.get(cur)
                    if c_end is None:
                        break
                    c_depth = span_depth[cur]
                    if c_depth >= max_depth:
                        break
                    cur = c_end
                    if c_depth > max_child_depth:
                        max_child_depth = c_depth
                elif "0" <= ch_v <= "9" and (cur + 1 == n or text[cur + 1] in ",}] \t\r\n"):
                    cur += 1
                elif ch_v == '"':
                    q_end_v = text.find('"', cur + 1)
                    if q_end_v != -1:
                        if fast_str:
                            cur = q_end_v + 1
                        else:
                            v_slice = text[cur + 1 : q_end_v]
                            if "\\" not in v_slice and v_slice.isprintable():
                                cur = q_end_v + 1
                            else:
                                next_c = _skip_str_end(cur)
                                if next_c is None:
                                    break
                                cur = next_c
                    else:
                        break
                else:
                    next_c = _skip_scalar_or_str_end(cur)
                    if next_c is None:
                        break
                    cur = next_c
                if cur < n and text[cur] in ws:
                    cur += 1
                    while cur < n and text[cur] in ws:
                        cur += 1
                if cur >= n:
                    break
                if text[cur] == ",":
                    cur += 1
                    if cur < n and text[cur] in ws:
                        cur += 1
                        while cur < n and text[cur] in ws:
                            cur += 1
                    continue
                if text[cur] == "}":
                    rel_depth = 1 + max_child_depth
                    if rel_depth <= max_depth:
                        end_p = cur + 1
                        span_end[start] = end_p
                        span_depth[start] = rel_depth
                        if end_p > min_needed_end:
                            needed.append(start)
                    break
                break
        else:
            cur = start + 1
            if cur < n and text[cur] in ws:
                cur += 1
                while cur < n and text[cur] in ws:
                    cur += 1
            if cur >= n:
                continue
            if text[cur] == "]":
                end_p = cur + 1
                span_end[start] = end_p
                span_depth[start] = 0
                if end_p > min_needed_end:
                    needed.append(start)
                continue
            if max_depth < 1:
                continue
            max_child_depth = 0
            while True:
                if cur >= n:
                    break
                ch_v = text[cur]
                if ch_v in "{[":
                    c_end = span_end.get(cur)
                    if c_end is None:
                        break
                    c_depth = span_depth[cur]
                    if c_depth >= max_depth:
                        break
                    cur = c_end
                    if c_depth > max_child_depth:
                        max_child_depth = c_depth
                elif "0" <= ch_v <= "9" and (cur + 1 == n or text[cur + 1] in ",}] \t\r\n"):
                    cur += 1
                elif ch_v == '"':
                    q_end_v = text.find('"', cur + 1)
                    if q_end_v != -1:
                        if fast_str:
                            cur = q_end_v + 1
                        else:
                            v_slice = text[cur + 1 : q_end_v]
                            if "\\" not in v_slice and v_slice.isprintable():
                                cur = q_end_v + 1
                            else:
                                next_c = _skip_str_end(cur)
                                if next_c is None:
                                    break
                                cur = next_c
                    else:
                        break
                else:
                    next_c = _skip_scalar_or_str_end(cur)
                    if next_c is None:
                        break
                    cur = next_c
                if cur < n and text[cur] in ws:
                    cur += 1
                    while cur < n and text[cur] in ws:
                        cur += 1
                if cur >= n:
                    break
                if text[cur] == ",":
                    cur += 1
                    if cur < n and text[cur] in ws:
                        cur += 1
                        while cur < n and text[cur] in ws:
                            cur += 1
                    continue
                if text[cur] == "]":
                    rel_depth = 1 + max_child_depth
                    if rel_depth <= max_depth:
                        end_p = cur + 1
                        span_end[start] = end_p
                        span_depth[start] = rel_depth
                        if end_p > min_needed_end:
                            needed.append(start)
                    break
                break

    return span_end, needed


def _build_json_span_index(
    text: str,
    max_depth: int = _MAX_JSON_AST_DEPTH,
    *,
    min_needed_end: int = 0,
) -> dict[int, tuple[_JsonObject | _JsonArray, int]]:
    """Build O(N) right-to-left memoized index of valid RFC 8259 JSON objects/arrays."""
    _, needed = _build_json_bounds(text, max_depth, min_needed_end=min_needed_end)
    if not needed:
        return {}
    ast_memo: dict[int, tuple[_JsonObject | _JsonArray, int]] = {}
    ast_depths: dict[int, int] = {}
    out_filtered: dict[int, tuple[_JsonObject | _JsonArray, int]] = {}
    for p in needed:
        parsed = _parse_json_span(text, p, max_depth, _memo=ast_memo, _memo_depths=ast_depths)
        if parsed is not None:
            out_filtered[p] = parsed
    return out_filtered


def _parse_json_span(
    text: str,
    start: int,
    max_depth: int = _MAX_JSON_AST_DEPTH,
    *,
    _memo: dict[int, tuple[_JsonObject | _JsonArray, int]] | None = None,
    _memo_depths: dict[int, int] | None = None,
) -> tuple[_JsonObject | _JsonArray, int] | None:
    """Parse exact-span RFC 8259 JSON object/array without reformatting untouched regions."""
    n = len(text)
    if start >= n or text[start] not in "{[":
        return None
    if _memo is not None and start in _memo:
        return _memo[start]

    def _skip_ws(idx: int) -> int:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        return idx

    def _parse_str(idx: int) -> tuple[_JsonStr, int] | None:
        if idx >= n or text[idx] != '"':
            return None
        q_end = text.find('"', idx + 1)
        if q_end != -1:
            slice_str = text[idx + 1 : q_end]
            if "\\" not in slice_str and slice_str.isprintable():
                return (_JSON_STR, idx, q_end + 1), q_end + 1
        pos = idx + 1
        while pos < n:
            ch = text[pos]
            if ord(ch) < 0x20:
                return None
            if ch == '"':
                return (_JSON_STR, idx, pos + 1), pos + 1
            if ch == "\\":
                pos += 1
                if pos >= n:
                    return None
                esc = text[pos]
                if esc in '"\\/bfnrt':
                    pos += 1
                elif esc == "u":
                    if pos + 5 > n:
                        return None
                    for hx in text[pos + 1 : pos + 5]:
                        if hx not in _HEX_DIGITS:
                            return None
                    pos += 5
                else:
                    return None
            else:
                pos += 1
        return None

    def _parse_val(idx: int, depth: int) -> tuple[_JsonNode, int, int] | None:
        if depth > max_depth or idx >= n:
            return None
        ch = text[idx]
        if ch == "{":
            res_o = _parse_obj(idx, depth)
            if res_o is None:
                return None
            return res_o[0], res_o[1], res_o[2]
        if ch == "[":
            res_a = _parse_arr(idx, depth)
            if res_a is None:
                return None
            return res_a[0], res_a[1], res_a[2]
        if ch == '"':
            res_s = _parse_str(idx)
            if res_s is None:
                return None
            return res_s[0], res_s[1], 0
        if ch in "-0123456789":
            num_m = _JSON_NUMBER_RE.match(text, idx)
            if num_m is None:
                return None
            return (_JSON_SCALAR, idx, num_m.end()), num_m.end(), 0
        if text.startswith("true", idx):
            return (_JSON_SCALAR, idx, idx + 4), idx + 4, 0
        if text.startswith("false", idx):
            return (_JSON_SCALAR, idx, idx + 5), idx + 5, 0
        if text.startswith("null", idx):
            return (_JSON_SCALAR, idx, idx + 4), idx + 4, 0
        return None

    def _parse_obj(idx: int, depth: int) -> tuple[_JsonObject, int, int] | None:
        if depth > max_depth:
            return None
        if _memo is not None and idx in _memo:
            assert _memo_depths is not None
            rel_d = _memo_depths[idx]
            if depth + rel_d > max_depth:
                return None
            cached_node = _memo[idx][0]
            if cached_node[0] != _JSON_OBJ:
                return None
            return cached_node, _memo[idx][1], rel_d
        cur = _skip_ws(idx + 1)
        if cur >= n:
            return None
        if text[cur] == "}":
            node_empty: _JsonObject = (_JSON_OBJ, idx, cur + 1, ())
            if _memo is not None and _memo_depths is not None:
                _memo[idx] = (node_empty, cur + 1)
                _memo_depths[idx] = 0
            return node_empty, cur + 1, 0
        if text[cur] != '"':
            return None
        pairs: list[tuple[_JsonStr, _JsonNode]] = []
        max_child_d = 0
        while True:
            key_res = _parse_str(cur)
            if key_res is None:
                return None
            key_node, cur = key_res
            cur = _skip_ws(cur)
            if cur >= n or text[cur] != ":":
                return None
            cur = _skip_ws(cur + 1)
            val_res = _parse_val(cur, depth + 1)
            if val_res is None:
                return None
            val_node, cur, child_d = val_res
            if child_d > max_child_d:
                max_child_d = child_d
            pairs.append((key_node, val_node))
            cur = _skip_ws(cur)
            if cur >= n:
                return None
            if text[cur] == ",":
                cur = _skip_ws(cur + 1)
                continue
            if text[cur] == "}":
                rel_d = 1 + max_child_d
                node_obj: _JsonObject = (_JSON_OBJ, idx, cur + 1, tuple(pairs))
                if _memo is not None and _memo_depths is not None:
                    _memo[idx] = (node_obj, cur + 1)
                    _memo_depths[idx] = rel_d
                return node_obj, cur + 1, rel_d
            return None

    def _parse_arr(idx: int, depth: int) -> tuple[_JsonArray, int, int] | None:
        if depth > max_depth:
            return None
        if _memo is not None and idx in _memo:
            assert _memo_depths is not None
            rel_d = _memo_depths[idx]
            if depth + rel_d > max_depth:
                return None
            cached_node = _memo[idx][0]
            if cached_node[0] != _JSON_ARR:
                return None
            return cached_node, _memo[idx][1], rel_d
        cur = _skip_ws(idx + 1)
        if cur >= n:
            return None
        if text[cur] == "]":
            node_empty_a: _JsonArray = (_JSON_ARR, idx, cur + 1, ())
            if _memo is not None and _memo_depths is not None:
                _memo[idx] = (node_empty_a, cur + 1)
                _memo_depths[idx] = 0
            return node_empty_a, cur + 1, 0
        items: list[_JsonNode] = []
        max_child_d = 0
        while True:
            val_res = _parse_val(cur, depth + 1)
            if val_res is None:
                return None
            val_node, cur, child_d = val_res
            if child_d > max_child_d:
                max_child_d = child_d
            items.append(val_node)
            cur = _skip_ws(cur)
            if cur >= n:
                return None
            if text[cur] == ",":
                cur = _skip_ws(cur + 1)
                continue
            if text[cur] == "]":
                rel_d = 1 + max_child_d
                node_arr: _JsonArray = (_JSON_ARR, idx, cur + 1, tuple(items))
                if _memo is not None and _memo_depths is not None:
                    _memo[idx] = (node_arr, cur + 1)
                    _memo_depths[idx] = rel_d
                return node_arr, cur + 1, rel_d
            return None

    if text[start] == "{":
        res_top_o = _parse_obj(start, 0)
        return (res_top_o[0], res_top_o[1]) if res_top_o is not None else None
    res_top_a = _parse_arr(start, 0)
    return (res_top_a[0], res_top_a[1]) if res_top_a is not None else None


def _redact_json_handle_str(
    text: str,
    snode: _JsonStr,
    is_sensitive: bool,
    depth: int,
    edits: list[tuple[int, int, str]],
    step0_flag: list[bool] | None = None,
) -> int:
    s_start = snode[1]
    s_end = snode[2]
    raw_s_slice = text[s_start:s_end]
    raw_inner_len = s_end - s_start - 2
    if "\\" not in raw_s_slice:
        val = raw_s_slice[1:-1]
    else:
        loaded_v = json.loads(raw_s_slice)
        assert isinstance(loaded_v, str)
        val = loaded_v
    if is_sensitive:
        if val == "":
            return 0
        val_s = val.strip()
        if val_s and val_s[0] == "r" and _is_already_redacted_placeholder(val_s):
            if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(val):
                step0_flag[0] = True
            return 0
        if (
            len(val_s) >= 22
            and val_s[0] in "bB"
            and _ALREADY_REDACTED_AUTH_STR_RE.fullmatch(val_s)
        ):
            if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(val):
                step0_flag[0] = True
            return 0
        if len(val) >= 5 and _may_have_redact_trigger(val):
            scrubbed_val, sub_c = _redact_core(val, depth + 1, _skip_trigger_check=True)
            if sub_c > 0 and _ALREADY_REDACTED_AUTH_STR_RE.fullmatch(scrubbed_val.strip()):
                edits.append((s_start, s_end, json.dumps(scrubbed_val, ensure_ascii=False)))
                if (
                    step0_flag is not None
                    and not step0_flag[0]
                    and _may_normalize_leaf(scrubbed_val)
                ):
                    step0_flag[0] = True
                return sub_c
        edits.append((s_start, s_end, f'"redacted {raw_inner_len} chars"'))
        return 1
    if len(val) >= 5 and _may_have_redact_trigger(val):
        scrubbed_val, sub_c = _redact_core(val, depth + 1, _skip_trigger_check=True)
        if sub_c > 0:
            edits.append((s_start, s_end, json.dumps(scrubbed_val, ensure_ascii=False)))
            if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(scrubbed_val):
                step0_flag[0] = True
            return sub_c
        if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(val):
            step0_flag[0] = True
        return 0
    if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(val):
        step0_flag[0] = True
    return 0


def _redact_json_walk(
    text: str,
    cur: _JsonNode,
    is_sensitive: bool,
    depth: int,
    edits: list[tuple[int, int, str]],
    step0_flag: list[bool] | None = None,
) -> int:
    total = 0
    kind = cur[0]
    if kind == _JSON_OBJ:
        for k_node, v_node in cast(_JsonObject, cur)[3]:
            raw_k_slice = text[k_node[1] : k_node[2]]
            if "\\" not in raw_k_slice:
                k_val = raw_k_slice[1:-1]
            else:
                loaded_k = json.loads(raw_k_slice)
                assert isinstance(loaded_k, str)
                k_val = loaded_k
            if len(k_val) >= 5:
                child_sensitive = is_sensitive or _is_sensitive_memory_kv_key(k_val)
                if _may_have_redact_trigger(k_val):
                    k_scrubbed, k_c = _redact_core(k_val, depth + 1, _skip_trigger_check=True)
                    if k_c > 0:
                        edits.append(
                            (
                                k_node[1],
                                k_node[2],
                                json.dumps(k_scrubbed, ensure_ascii=False),
                            )
                        )
                        total += k_c
                    if step0_flag is not None and not step0_flag[0]:
                        k_eff = k_scrubbed if k_c > 0 else k_val
                        if _may_normalize_leaf(k_eff) or (
                            depth > 0 and k_eff.endswith(("chars", "[REDACTED]"))
                        ):
                            step0_flag[0] = True
                elif (
                    step0_flag is not None
                    and not step0_flag[0]
                    and (
                        _may_normalize_leaf(k_val)
                        or (depth > 0 and k_val.endswith(("chars", "[REDACTED]")))
                    )
                ):
                    step0_flag[0] = True
            else:
                child_sensitive = is_sensitive
                if step0_flag is not None and not step0_flag[0] and _may_normalize_leaf(k_val):
                    step0_flag[0] = True
            vk = v_node[0]
            if vk == _JSON_SCALAR:
                if child_sensitive and text[v_node[1] : v_node[2]] != "null":
                    edits.append(
                        (
                            v_node[1],
                            v_node[2],
                            f'"redacted {v_node[2] - v_node[1]} chars"',
                        )
                    )
                    total += 1
            elif vk == _JSON_STR:
                total += _redact_json_handle_str(
                    text, cast(_JsonStr, v_node), child_sensitive, depth, edits, step0_flag
                )
            else:
                total += _redact_json_walk(
                    text, v_node, child_sensitive, depth, edits, step0_flag
                )
    elif kind == _JSON_ARR:
        for item in cast(_JsonArray, cur)[3]:
            ik = item[0]
            if ik == _JSON_SCALAR:
                if is_sensitive and text[item[1] : item[2]] != "null":
                    edits.append(
                        (
                            item[1],
                            item[2],
                            f'"redacted {item[2] - item[1]} chars"',
                        )
                    )
                    total += 1
            elif ik == _JSON_STR:
                total += _redact_json_handle_str(
                    text, cast(_JsonStr, item), is_sensitive, depth, edits, step0_flag
                )
            else:
                total += _redact_json_walk(text, item, is_sensitive, depth, edits, step0_flag)
    elif kind == _JSON_STR:
        total += _redact_json_handle_str(
            text, cast(_JsonStr, cur), is_sensitive, depth, edits, step0_flag
        )
    elif kind == _JSON_SCALAR and is_sensitive and text[cur[1] : cur[2]] != "null":
        edits.append((cur[1], cur[2], f'"redacted {cur[2] - cur[1]} chars"'))
        total += 1
    return total


def _redact_json_ast(
    text: str,
    node: _JsonObject | _JsonArray,
    depth: int,
    *,
    sensitive_parent: bool = False,
    step0_flag: list[bool] | None = None,
) -> tuple[str, int]:
    edits: list[tuple[int, int, str]] = []
    total = _redact_json_walk(text, node, sensitive_parent, depth, edits, step0_flag)
    n_start, n_end = node[1], node[2]
    if not edits:
        return text[n_start:n_end], 0
    parts: list[str] = []
    cursor = n_start
    for ed_start, ed_end, repl in edits:
        parts.append(text[cursor:ed_start])
        parts.append(repl)
        cursor = ed_end
    parts.append(text[cursor:n_end])
    return "".join(parts), total


_KV_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-\u0130\u0131\u017f\u212a"
)


def _is_word_char(ch: str) -> bool:
    return ch == "_" or ch.isalnum()


class _QuoteEnclosureTracker:
    """Incremental O(N) tracker of active quote enclosures with O(log N) random access."""

    __slots__ = (
        "_text",
        "_n",
        "_has_quotes",
        "_cursor",
        "_nodes",
        "_head_id",
        "_ev_pos",
        "_ev_head",
        "_last_head",
        "_last_tuple",
    )

    def __init__(self, text: str) -> None:
        self._text = text
        self._n = len(text)
        self._has_quotes = '"' in text or "'" in text
        self._cursor = 0
        self._nodes: list[tuple[str, int, int, int]] = []
        self._head_id = -1
        self._ev_pos: list[int] = []
        self._ev_head: list[int] = []
        self._last_head = -2
        self._last_tuple: tuple[tuple[str, int, int], ...] = ()

    def _advance_to(self, limit: int) -> None:
        text = self._text
        idx = self._cursor
        nodes = self._nodes
        head_id = self._head_id
        ev_pos = self._ev_pos
        ev_head = self._ev_head
        search = _QUOTE_EVENT_RE.search

        while idx < limit:
            m = search(text, idx, limit)
            if m is None:
                idx = limit
                break
            m_start = m.start()
            m_end = m.end()
            ch = text[m_start]
            if ch in "\r\n":
                if head_id != -1:
                    head_id = -1
                    ev_pos.append(m_start + 1)
                    ev_head.append(-1)
                idx = m_end
                continue
            if ch == "\\":
                k = m_end - m_start
                q_idx = m_end
                if q_idx >= limit:
                    idx = m_start
                    break
                qc = text[q_idx]
                if qc not in "\"'":
                    idx = q_idx
                    continue
            else:
                k = 0
                q_idx = m_start
                qc = ch

            if head_id != -1 and nodes[head_id][0] == qc:
                top_bs = nodes[head_id][1]
                mod = 2 * (top_bs + 1)
                if k % mod == top_bs:
                    head_id = nodes[head_id][3]
                    ev_pos.append(q_idx + 1)
                    ev_head.append(head_id)
                    idx = q_idx + 1
                    continue

            is_valid_boundary = (
                m_start == 0
                or text[m_start - 1].isspace()
                or text[m_start - 1] in "([{:;=,&"
                or (head_id != -1 and m_start - 1 == nodes[head_id][2])
            )
            if is_valid_boundary:
                if head_id == -1:
                    parity_ok = _is_valid_escape_bs(k)
                else:
                    top_q, top_bs, _, _ = nodes[head_id]
                    if qc == top_q:
                        parity_ok = k == 2 * top_bs + 1
                    else:
                        parity_ok = k == top_bs or (qc == "'" and k == 0)
                if parity_ok:
                    new_id = len(nodes)
                    nodes.append((qc, k, q_idx, head_id))
                    head_id = new_id
                    ev_pos.append(q_idx + 1)
                    ev_head.append(head_id)
            idx = q_idx + 1

        self._cursor = idx
        self._head_id = head_id

    def stack_at(self, target_pos: int) -> tuple[tuple[str, int, int], ...]:
        if not self._has_quotes or target_pos <= 0:
            return ()
        limit = min(target_pos, self._n)
        if limit > self._cursor:
            self._advance_to(limit)
        if limit >= self._cursor:
            head_id = self._head_id
        else:
            ev_idx = bisect_right(self._ev_pos, limit) - 1
            head_id = self._ev_head[ev_idx] if ev_idx >= 0 else -1
        if head_id == -1:
            return ()
        nodes = self._nodes
        if nodes[head_id][3] == -1:
            n0 = nodes[head_id]
            return ((n0[0], n0[1], n0[2]),)
        if head_id == self._last_head:
            return self._last_tuple
        rev: list[tuple[str, int, int]] = []
        cur = head_id
        while cur != -1:
            qc, k, q_idx, prev_id = nodes[cur]
            rev.append((qc, k, q_idx))
            cur = prev_id
        rev.reverse()
        tup = tuple(rev)
        self._last_head = head_id
        self._last_tuple = tup
        return tup


def _enclosing_quote_info(
    text: str,
    anchor: int,
    *,
    tracker: _QuoteEnclosureTracker | None = None,
) -> tuple[str, tuple[tuple[str, int, int], ...]] | None:
    if anchor <= 0:
        return None
    pos = anchor
    while pos > 0 and text[pos - 1] in "([{":
        pos -= 1
    if pos <= 0 or text[pos - 1] not in "\"'":
        return None
    qchar = text[pos - 1]
    bs = _count_leading_backslashes(text, pos - 1)
    if not _is_valid_escape_bs(bs):
        return None
    open_start = pos - 1 - bs
    if open_start < 0 or (open_start > 0 and _is_word_char(text[open_start - 1])):
        return None
    tr = tracker if tracker is not None else _QuoteEnclosureTracker(text)
    stack = tr.stack_at(pos)
    if not stack:
        return None
    top_q, top_bs, top_q_pos = stack[-1]
    if top_q == qchar and top_bs == bs and top_q_pos == pos - 1:
        return ("\\" * bs) + qchar, stack[:-1]
    return None


def _enclosing_quote_prefix(
    text: str,
    anchor: int,
    *,
    tracker: _QuoteEnclosureTracker | None = None,
) -> str | None:
    info = _enclosing_quote_info(text, anchor, tracker=tracker)
    return info[0] if info is not None else None


def _has_matching_enclosing_quote(
    text: str,
    anchor: int,
    q_prefix: str,
    *,
    tracker: _QuoteEnclosureTracker | None = None,
) -> bool:
    if not q_prefix or anchor <= 0:
        return False
    return _enclosing_quote_prefix(text, anchor, tracker=tracker) == q_prefix


def _skip_outer_quotes_for_escaped_tail(
    text: str,
    span_end: int,
    bs: int,
    *,
    enclosing_stack: tuple[tuple[str, int, int], ...] = (),
) -> int:
    pos = span_end
    n = len(text)
    if bs <= 0 or not enclosing_stack:
        return pos
    cur_bs = bs
    for outer_qc, outer_bs, _ in reversed(enclosing_stack):
        if outer_bs > cur_bs:
            continue
        if (
            pos + outer_bs < n
            and all(text[pos + i] == "\\" for i in range(outer_bs))
            and text[pos + outer_bs] == outer_qc
        ):
            pos += outer_bs + 1
            cur_bs = outer_bs
            if outer_bs == 0:
                break
        else:
            break
    return pos


def _is_clean_redacted_tail_quoted(
    text: str,
    span_end: int,
    bs: int,
    *,
    enclosing_stack: tuple[tuple[str, int, int], ...] = (),
) -> bool:
    check_pos = _skip_outer_quotes_for_escaped_tail(
        text, span_end, bs, enclosing_stack=enclosing_stack
    )
    return _VALID_TAIL_ENCLOSED_QUOTE_RE.match(text, check_pos) is not None


def _is_clean_redacted_tail_unquoted(
    text: str,
    val_end: int,
    *,
    enclosing_anchor: int,
    allow_quoted_enclosure: bool,
    tracker: _QuoteEnclosureTracker | None = None,
    enclosing_info: tuple[str, tuple[tuple[str, int, int], ...]] | None = None,
) -> bool:
    n = len(text)
    check_idx = val_end
    if allow_quoted_enclosure:
        while check_idx < n and text[check_idx] in ")]}":
            check_idx += 1
    if check_idx < n and text[check_idx] in "\"'\\":
        bs = 0
        q_pos = check_idx
        while q_pos < n and text[q_pos] == "\\":
            bs += 1
            q_pos += 1
        if q_pos < n and text[q_pos] in "\"'" and _is_valid_escape_bs(bs):
            q_prefix = text[check_idx : q_pos + 1]
            info = enclosing_info
            if info is None and allow_quoted_enclosure:
                tr = tracker if tracker is not None else _QuoteEnclosureTracker(text)
                info = _enclosing_quote_info(text, enclosing_anchor, tracker=tr)
            if info is not None and info[0] == q_prefix:
                return _is_clean_redacted_tail_quoted(
                    text, q_pos + 1, bs, enclosing_stack=info[1]
                )
        return False
    if allow_quoted_enclosure:
        return _VALID_TAIL_ENCLOSED_QUOTE_RE.match(text, val_end) is not None
    return _VALID_TAIL_UNQUOTED_RE.match(text, val_end) is not None


def _scan_unquoted_value_end(
    text: str,
    val_start: int,
    *,
    allow_quoted_enclosure: bool,
    enclosing_q_prefix: str | None = None,
    enclosing_outer_stack: tuple[tuple[str, int, int], ...] = (),
    bal_cache: dict[int, int | None] | None = None,
) -> int:
    n = len(text)
    idx = val_start
    comma_re = _COMMA_SEMI_QUOTED_RE if allow_quoted_enclosure else _COMMA_SEMI_UNQUOTED_RE
    stop_bracket_re = (
        _VALID_TAIL_STOP_BRACKET_QUOTED_RE
        if allow_quoted_enclosure
        else _VALID_TAIL_STOP_BRACKET_UNQUOTED_RE
    )
    while idx < n:
        ch = text[idx]
        if ch.isspace():
            break
        if idx == val_start and ch == "r":
            red_m = _REDACTED_N_CHARS_RE.match(text, idx)
            if red_m is not None:
                idx = red_m.end()
                continue
        if ch in "{[":
            c_end = _find_balanced_container_end(text, idx, cache=bal_cache)
            if c_end is None:
                return n
            idx = c_end
            continue
        if ch in "\"'\\":
            if enclosing_q_prefix is not None:
                k = 0
                while idx + k < n and text[idx + k] == "\\":
                    k += 1
                if idx + k < n and text[idx + k] in "\"'":
                    qc = text[idx + k]
                    bs_enc = len(enclosing_q_prefix) - 1
                    q_enc = enclosing_q_prefix[-1]
                    mod_enc = 2 * (bs_enc + 1)
                    if qc == q_enc and k % mod_enc == bs_enc:
                        close_q_start = idx + k - bs_enc
                        close_q_end = idx + k + 1
                        if _is_clean_redacted_tail_quoted(
                            text,
                            close_q_end,
                            bs_enc,
                            enclosing_stack=enclosing_outer_stack,
                        ):
                            return close_q_start
                    elif qc == q_enc and k % mod_enc == 2 * bs_enc + 1:
                        idx += k + 1
                        continue
            q_res = _match_quoted_span(text, idx)
            if q_res is not None:
                q_closed, _, _, q_span_end, _, _ = q_res
                if not q_closed:
                    return q_span_end
                idx = q_span_end
                continue
            if ch == "\\":
                k = 1
                while idx + k < n and text[idx + k] == "\\":
                    k += 1
                idx += k
                continue
            idx += 1
            continue
        if ch in ",;":
            if comma_re.match(text, idx + 1) is not None:
                break
            idx += 1
            continue
        if ch == "&":
            if _AMP_TAIL_RE.match(text, idx) is not None:
                break
            idx += 1
            continue
        if ch in ")]}":
            if stop_bracket_re.match(text, idx) is not None:
                break
            if enclosing_q_prefix is not None:
                br_end = idx + 1
                while br_end < n and text[br_end] in ")]}":
                    br_end += 1
                if text.startswith(enclosing_q_prefix, br_end) and _is_clean_redacted_tail_quoted(
                    text,
                    br_end + len(enclosing_q_prefix),
                    len(enclosing_q_prefix) - 1,
                    enclosing_stack=enclosing_outer_stack,
                ):
                    break
            idx += 1
            continue
        idx += 1
    return idx


def _search_valid_kv(
    text: str, start: int, *, eq_only: bool = False, limit: int | None = None
) -> _KvMatch | None:
    n = len(text)
    if start >= n:
        return None
    end_lim = min(n, limit) if limit is not None else n
    if eq_only or ":" not in text:
        s_pos = start
        while s_pos < end_lim:
            sep_start = text.find("=", s_pos, end_lim)
            if sep_start == -1:
                return None
            s_pos = sep_start + 1
            end_k = sep_start
            if (
                end_k > start
                and text[end_k - 1] not in _SENSITIVE_KEY_END_CHARS
                and text[end_k - 1] not in "\"'"
            ):
                if not text[end_k - 1].isspace():
                    continue
                while end_k > start and text[end_k - 1].isspace():
                    end_k -= 1
            if end_k <= start:
                continue

            last_ch = text[end_k - 1]
            if last_ch in "\"'":
                qchar = last_ch
                bs_idx = end_k - 1
                bs_close = 0
                while bs_idx > start and text[bs_idx - 1] == "\\":
                    bs_close += 1
                    bs_idx -= 1
                if bs_idx <= start or text[bs_idx - 1] not in _SENSITIVE_KEY_END_CHARS:
                    continue
                if not _is_valid_escape_bs(bs_close):
                    continue
                qkey_start = bs_idx
                while qkey_start > start and text[qkey_start - 1] in _KV_KEY_CHARS:
                    qkey_start -= 1
                if (
                    bs_idx - qkey_start < 5
                    or qkey_start <= start
                    or text[qkey_start - 1] != qchar
                ):
                    continue
                kq_pos = qkey_start - 1
                if kq_pos > 0 and _is_word_char(text[kq_pos - 1]):
                    continue
                qkey = text[qkey_start:bs_idx]
                if _SENSITIVE_KEY_TAIL_RE.search(qkey, max(0, len(qkey) - 16)) is None:
                    continue
                if (
                    _KV_PREFIXED_END_RE.search(qkey, max(0, len(qkey) - 24)) is None
                    and _SENSITIVE_KEY_EXACT_RE.match(qkey, 0) is None
                ):
                    continue
                if not _is_sensitive_memory_kv_key(qkey):
                    continue
                bs_open = (
                    _count_leading_backslashes(text, kq_pos)
                    if kq_pos > 0 and text[kq_pos - 1] == "\\"
                    else 0
                )
                diff = bs_open - bs_close
                if diff < 0 or diff % (2 * (bs_close + 1)) != 0:
                    continue
                val_start = sep_start + 1
                while val_start < n and text[val_start].isspace():
                    val_start += 1
                return _KvMatch(
                    anchor=kq_pos - bs_close,
                    val_start=val_start,
                    raw_key=qkey,
                    sep=text[end_k:val_start],
                    key_bs=bs_close,
                    match_end=val_start,
                )

            if last_ch in _SENSITIVE_KEY_END_CHARS:
                run_start = end_k
                while run_start > 0 and text[run_start - 1] in _KV_KEY_CHARS:
                    run_start -= 1
                eff_start = run_start if run_start >= start else start
                while eff_start < end_k and eff_start > 0 and _is_word_char(text[eff_start - 1]):
                    eff_start += 1
                if eff_start >= end_k or end_k - eff_start < 5:
                    continue
                cand = text[eff_start:end_k]
                raw_key_eq: str | None = None
                anchor_off_eq = 0
                if "." not in cand and "-" not in cand and "_" not in cand:
                    folded_low = _re_ci_fold(cand).lower()
                    if (
                        folded_low in _EXACT_SENSITIVE_KV_KEYS_CI
                        or _SENSITIVE_KEY_EXACT_RE.match(cand, 0) is not None
                    ):
                        raw_key_eq = cand
                else:
                    if _SENSITIVE_KEY_TAIL_RE.search(cand, max(0, len(cand) - 16)) is None:
                        continue
                    if _KV_PREFIXED_END_RE.search(cand, max(0, len(cand) - 24)) is not None:
                        raw_key_eq = cand
                        anchor_off_eq = 0
                    else:
                        seg_start = cand.rfind(".") + 1
                        offsets = [seg_start]
                        h_pos = len(cand)
                        for _ in range(3):
                            h_idx = cand.rfind("-", seg_start, h_pos)
                            if h_idx == -1:
                                break
                            offsets.append(h_idx + 1)
                            h_pos = h_idx
                        for st in sorted(set(offsets)):
                            if _SENSITIVE_KEY_EXACT_RE.match(cand, st) is not None:
                                raw_key_eq = cand[st:]
                                anchor_off_eq = st
                                break

                if raw_key_eq is None or not _is_sensitive_memory_kv_key(raw_key_eq):
                    continue
                val_start = sep_start + 1
                while val_start < n and text[val_start].isspace():
                    val_start += 1
                return _KvMatch(
                    anchor=eff_start + anchor_off_eq,
                    val_start=val_start,
                    raw_key=raw_key_eq,
                    sep=text[end_k:val_start],
                    key_bs=0,
                    match_end=val_start,
                )
        return None

    sep_iter = (
        _COLON_EQ_RE.finditer(text, start, end_lim)
        if limit is not None
        else _COLON_EQ_RE.finditer(text, start)
    )
    for sep_m in sep_iter:
        sep_start = sep_m.start()
        end_k = sep_start
        while end_k > start and text[end_k - 1].isspace():
            end_k -= 1
        if end_k <= start:
            continue

        last_ch = text[end_k - 1]
        if last_ch in "\"'":
            qchar = last_ch
            bs_idx = end_k - 1
            bs_close = 0
            while bs_idx > start and text[bs_idx - 1] == "\\":
                bs_close += 1
                bs_idx -= 1
            if bs_idx <= start or text[bs_idx - 1] not in _SENSITIVE_KEY_END_CHARS:
                continue
            if not _is_valid_escape_bs(bs_close):
                continue
            qkey_start = bs_idx
            while qkey_start > start and text[qkey_start - 1] in _KV_KEY_CHARS:
                qkey_start -= 1
            if (
                bs_idx - qkey_start < 5
                or qkey_start <= start
                or text[qkey_start - 1] != qchar
            ):
                continue
            kq_pos = qkey_start - 1
            if kq_pos > 0 and _is_word_char(text[kq_pos - 1]):
                continue
            qkey = text[qkey_start:bs_idx]
            if _SENSITIVE_KEY_TAIL_RE.search(qkey, max(0, len(qkey) - 16)) is None:
                continue
            if (
                _KV_PREFIXED_END_RE.search(qkey, max(0, len(qkey) - 24)) is None
                and _SENSITIVE_KEY_EXACT_RE.match(qkey, 0) is None
            ):
                continue
            if not _is_sensitive_memory_kv_key(qkey):
                continue
            bs_open = (
                _count_leading_backslashes(text, kq_pos)
                if kq_pos > 0 and text[kq_pos - 1] == "\\"
                else 0
            )
            diff = bs_open - bs_close
            if diff < 0 or diff % (2 * (bs_close + 1)) != 0:
                continue
            val_start = sep_m.end()
            while val_start < n and text[val_start].isspace():
                val_start += 1
            return _KvMatch(
                anchor=kq_pos - bs_close,
                val_start=val_start,
                raw_key=qkey,
                sep=text[end_k:val_start],
                key_bs=bs_close,
                match_end=val_start,
            )

        if last_ch in _SENSITIVE_KEY_END_CHARS:
            run_start = end_k
            while run_start > 0 and text[run_start - 1] in _KV_KEY_CHARS:
                run_start -= 1
            eff_start = run_start if run_start >= start else start
            while eff_start < end_k and eff_start > 0 and _is_word_char(text[eff_start - 1]):
                eff_start += 1
            if eff_start >= end_k or end_k - eff_start < 5:
                continue
            cand = text[eff_start:end_k]
            raw_key: str | None = None
            anchor_off = 0
            if "." not in cand and "-" not in cand and "_" not in cand:
                folded_low = _re_ci_fold(cand).lower()
                if (
                    folded_low in _EXACT_SENSITIVE_KV_KEYS_CI
                    or _SENSITIVE_KEY_EXACT_RE.match(cand, 0) is not None
                ):
                    raw_key = cand
            else:
                if _SENSITIVE_KEY_TAIL_RE.search(cand, max(0, len(cand) - 16)) is None:
                    continue
                if _KV_PREFIXED_END_RE.search(cand, max(0, len(cand) - 24)) is not None:
                    raw_key = cand
                    anchor_off = 0
                else:
                    seg_start = cand.rfind(".") + 1
                    offsets = [seg_start]
                    h_pos = len(cand)
                    for _ in range(3):
                        h_idx = cand.rfind("-", seg_start, h_pos)
                        if h_idx == -1:
                            break
                        offsets.append(h_idx + 1)
                        h_pos = h_idx
                    for st in sorted(set(offsets)):
                        if _SENSITIVE_KEY_EXACT_RE.match(cand, st) is not None:
                            raw_key = cand[st:]
                            anchor_off = st
                            break

            if raw_key is None or not _is_sensitive_memory_kv_key(raw_key):
                continue
            val_start = sep_m.end()
            while val_start < n and text[val_start].isspace():
                val_start += 1
            return _KvMatch(
                anchor=eff_start + anchor_off,
                val_start=val_start,
                raw_key=raw_key,
                sep=text[end_k:val_start],
                key_bs=0,
                match_end=val_start,
            )
    return None


def _re_escape_quoted(inner: str, prefix: str) -> str:
    return f"{prefix}{inner}{prefix}"


def _scrub_auth_value_at(
    text: str,
    val_start: int,
    *,
    enclosing_anchor: int,
    allow_quoted_enclosure: bool,
    depth: int,
    enclosing_stack: tuple[tuple[str, int, int], ...] = (),
    enclosing_q_prefix: str | None = None,
    enclosing_outer_stack: tuple[tuple[str, int, int], ...] = (),
    tracker: _QuoteEnclosureTracker | None = None,
    bal_cache: dict[int, int | None] | None = None,
) -> tuple[str, int, int] | None:
    """Scrub token after Bearer/Basic at val_start; return (repl, end_idx, count) or None."""
    n = len(text)
    if val_start >= n:
        return None

    if text[val_start] == "r":
        red_m = _REDACTED_N_CHARS_RE.match(text, val_start)
        if red_m is not None and _is_clean_redacted_tail_unquoted(
            text,
            red_m.end(),
            enclosing_anchor=enclosing_anchor,
            allow_quoted_enclosure=allow_quoted_enclosure,
            tracker=tracker,
        ):
            return None

    if text[val_start] in "\"'\\":
        q_res = _match_quoted_span(text, val_start)
        if q_res is not None:
            closed, inner_start, inner_end, span_end, prefix, _ = q_res
            bs = len(prefix) - 1
            if closed and _is_clean_redacted_tail_quoted(
                text, span_end, bs, enclosing_stack=enclosing_stack
            ):
                inner = text[inner_start:inner_end]
                if inner_start < inner_end:
                    if _is_already_redacted_placeholder(inner):
                        return None
                    return f"{prefix}redacted {len(inner)} chars{prefix}", span_end, 1
            if not closed:
                raw_len = span_end - val_start
                return f"redacted {raw_len} chars", span_end, 1

    end_idx = _scan_unquoted_value_end(
        text,
        val_start,
        allow_quoted_enclosure=allow_quoted_enclosure,
        enclosing_q_prefix=enclosing_q_prefix,
        enclosing_outer_stack=enclosing_outer_stack,
        bal_cache=bal_cache,
    )
    if end_idx <= val_start:
        return None
    return f"redacted {end_idx - val_start} chars", end_idx, 1


def _scrub_kv_value_at(
    text: str,
    kv: _KvMatch,
    depth: int,
    *,
    tracker: _QuoteEnclosureTracker | None = None,
    json_index: dict[int, tuple[_JsonObject | _JsonArray, int]] | None = None,
    json_bounds: dict[int, int] | None = None,
    bal_cache: dict[int, int | None] | None = None,
) -> tuple[str, int, int] | None:
    """Scrub KV value starting at kv.val_start; return (replacement, end_idx, count) or None."""
    n = len(text)
    val_start = kv.val_start
    if val_start >= n:
        return None

    tr = tracker if tracker is not None else _QuoteEnclosureTracker(text)
    enc_info = (
        _enclosing_quote_info(text, kv.anchor, tracker=tr)
        if (kv.key_bs == 0 and kv.anchor > 0 and text[kv.anchor - 1] in "\"'([{")
        else None
    )
    enclosing_q_prefix = enc_info[0] if enc_info is not None else None
    allow_quoted_enclosure = enclosing_q_prefix is not None
    enclosing_outer_stack = enc_info[1] if enc_info is not None else ()
    kv_enclosing_stack: tuple[tuple[str, int, int], ...] | None = None

    def _get_kv_stack() -> tuple[tuple[str, int, int], ...]:
        nonlocal kv_enclosing_stack
        if kv_enclosing_stack is None:
            kv_enclosing_stack = tr.stack_at(kv.anchor)
        return kv_enclosing_stack

    is_auth_colon = kv.raw_key.strip().lower() == "authorization" and ":" in kv.sep

    # 1. Check Authorization: Bearer/Basic ... or key=Bearer/Basic ...
    if text[val_start] in "bB":
        auth_m = _AUTH_SCHEME_RE.match(text, val_start)
        if auth_m is not None:
            scheme = auth_m.group("scheme")
            ws = auth_m.group("ws")
            auth_val_start = auth_m.end()
            auth_stack = (
                _get_kv_stack()
                if (allow_quoted_enclosure or (auth_val_start < n and text[auth_val_start] == "\\"))
                else ()
            )
            auth_res = _scrub_auth_value_at(
                text,
                auth_val_start,
                enclosing_anchor=kv.anchor,
                allow_quoted_enclosure=allow_quoted_enclosure,
                depth=depth,
                enclosing_stack=auth_stack,
                enclosing_q_prefix=enclosing_q_prefix,
                enclosing_outer_stack=enclosing_outer_stack,
                tracker=tr,
                bal_cache=bal_cache,
            )
            if is_auth_colon:
                if auth_res is None:
                    clean_end = auth_val_start
                    if auth_val_start < n and text[auth_val_start] == "r":
                        rm = _REDACTED_N_CHARS_RE.match(text, auth_val_start)
                        if rm is not None:
                            clean_end = rm.end()
                    elif auth_val_start < n and text[auth_val_start] in "\"'\\":
                        qr = _match_quoted_span(text, auth_val_start)
                        if qr is not None:
                            clean_end = qr[3]
                    return "", clean_end, 0
                repl, end_idx, sub_c = auth_res
                return f"{scheme}{ws}{repl}", end_idx, sub_c
            # e.g. Authorization=Bearer tok -> redact both scheme and token
            if auth_res is not None:
                repl, end_idx, sub_c = auth_res
                return f"redacted {len(scheme)} chars{ws}{repl}", end_idx, 1 + sub_c
            # Token already redacted, only scheme remains unredacted
            return f"redacted {len(scheme)} chars", auth_m.start("ws"), 1

    # 2. Check structured JSON container {...} or [...]
    if text[val_start] in "{[":
        if json_index is not None:
            parsed = json_index.get(val_start)
        elif json_bounds is not None and val_start not in json_bounds:
            parsed = None
        else:
            parsed = _parse_json_span(text, val_start)
        if parsed is not None:
            node, json_end = parsed
            if _VALID_STRUCTURED_TAIL_RE.match(text, json_end) is not None:
                scrubbed_json, sub_c = _redact_json_ast(
                    text, node, depth, sensitive_parent=True
                )
                if sub_c == 0:
                    return None
                return scrubbed_json, json_end, sub_c
        else:
            bal_end = _find_balanced_container_end(text, val_start, cache=bal_cache)
            if bal_end is not None and (
                _VALID_STRUCTURED_TAIL_RE.match(text, bal_end) is not None
                or (
                    kv.key_bs > 0
                    and _VALID_STRUCTURED_TAIL_RE.match(
                        text,
                        _skip_outer_quotes_for_escaped_tail(
                            text, bal_end, kv.key_bs, enclosing_stack=_get_kv_stack()
                        ),
                    )
                    is not None
                )
            ):
                raw_container = text[val_start:bal_end]
                try:
                    unescaped = json.loads('"' + raw_container + '"')
                except json.JSONDecodeError:
                    unescaped = None
                if isinstance(unescaped, str):
                    inner_parsed = _parse_json_span(unescaped, 0)
                    if inner_parsed is not None and inner_parsed[1] == len(unescaped):
                        inner_scrubbed, sub_c = _redact_json_ast(
                            unescaped, inner_parsed[0], depth + 1, sensitive_parent=True
                        )
                        if sub_c == 0:
                            return None
                        re_escaped = json.dumps(inner_scrubbed, ensure_ascii=False)[1:-1]
                        return re_escaped, bal_end, sub_c
                # Balanced non-JSON container under sensitive key -> scrub whole container
                return f"redacted {bal_end - val_start} chars", bal_end, 1

    # 3. Check already-redacted unquoted placeholder
    if text[val_start] == "r":
        red_m = _REDACTED_N_CHARS_RE.match(text, val_start)
        if red_m is not None and _is_clean_redacted_tail_unquoted(
            text,
            red_m.end(),
            enclosing_anchor=kv.anchor,
            allow_quoted_enclosure=allow_quoted_enclosure,
            tracker=tr,
            enclosing_info=enc_info,
        ):
            return None

    # 4. Check quoted / escaped-quoted string value
    if text[val_start] in "\"'\\":
        q_res = _match_quoted_span(text, val_start)
        if q_res is not None:
            closed, inner_start, inner_end, span_end, prefix, _ = q_res
            bs = len(prefix) - 1
            if closed and _is_clean_redacted_tail_quoted(
                text, span_end, bs, enclosing_stack=_get_kv_stack() if bs > 0 else ()
            ):
                inner = text[inner_start:inner_end]
                if inner == "" or _is_already_redacted_placeholder(inner):
                    return None
                if is_auth_colon:
                    if _ALREADY_REDACTED_AUTH_STR_RE.fullmatch(inner.strip()):
                        return None
                    if _AUTH_PREFIX_STR_RE.match(inner):
                        scrubbed_inner, sub_c = _redact_core(inner, depth + 1)
                        if sub_c > 0 and _ALREADY_REDACTED_AUTH_STR_RE.fullmatch(
                            scrubbed_inner.strip()
                        ):
                            return _re_escape_quoted(scrubbed_inner, prefix), span_end, sub_c
                return f"{prefix}redacted {len(inner)} chars{prefix}", span_end, 1
            if not closed:
                raw_len = span_end - val_start
                return f"redacted {raw_len} chars", span_end, 1

    # 5. Unquoted value or dirty-tail fallback
    end_idx = _scan_unquoted_value_end(
        text,
        val_start,
        allow_quoted_enclosure=allow_quoted_enclosure,
        enclosing_q_prefix=enclosing_q_prefix,
        enclosing_outer_stack=enclosing_outer_stack,
        bal_cache=bal_cache,
    )
    if end_idx <= val_start:
        return None
    return f"redacted {end_idx - val_start} chars", end_idx, 1


_URL_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")


def _search_url_userinfo(text: str, start: int) -> re.Match[str] | None:
    if "@" not in text:
        return None
    pos = start
    while True:
        sep = text.find("://", pos)
        if sep == -1:
            return None
        s = sep
        while s > start and text[s - 1] in _URL_SCHEME_CHARS:
            s -= 1
        while s < sep and not ("a" <= text[s] <= "z" or "A" <= text[s] <= "Z"):
            s += 1
        if s < sep:
            m = _URL_USERINFO_RE.match(text, s)
            if m is not None:
                return m
        pos = sep + 3


def _may_have_redact_trigger(text: str) -> bool:
    n = len(text)
    if n < 5:
        return False
    if "-----BEGIN" in text:
        return True
    if n >= 10 and (
        "sk-" in text
        or "gh" in text
        or "xox" in text
        or "AKIA" in text
        or "AIza" in text
        or "eyJ" in text
    ):
        return True
    if "://" in text and "@" in text:
        return True
    if "\\" in text and ("{" in text or "[" in text):
        return True
    has_kv = ":" in text or "=" in text
    has_b = "b" in text or "B" in text
    if not (has_kv or has_b):
        return False
    low = _re_ci_fold(text).lower()
    if has_b and ("bearer" in low or "basic" in low):
        return True
    if has_kv:
        return (
            "token" in low
            or "secret" in low
            or "key" in low
            or "password" in low
            or "passwd" in low
            or "cookie" in low
            or "credential" in low
            or "authorization" in low
            or "bearer" in low
        )
    return False


def _earliest_redact_trigger(text: str) -> int:
    n = len(text)
    min_pos = n
    if "://" in text and "@" in text:
        return 0
    for needle in ("-----BEGIN", "\\"):
        idx = text.find(needle)
        if idx != -1 and idx < min_pos:
            min_pos = idx
    if n >= 10:
        for needle in ("sk-", "gh", "xox", "AKIA", "AIza", "eyJ"):
            idx = text.find(needle)
            if idx != -1 and idx < min_pos:
                min_pos = idx
    if ":" in text or "=" in text or "b" in text or "B" in text:
        low = _re_ci_fold(text).lower()
        if len(low) != n:
            return 0
        for kw in (
            "bearer",
            "basic",
            "token",
            "secret",
            "key",
            "password",
            "passwd",
            "cookie",
            "credential",
            "authorization",
        ):
            idx = low.find(kw)
            if idx != -1 and idx < min_pos:
                min_pos = idx
    return min_pos


def _redact_core(
    text: str,
    depth: int = 0,
    *,
    _json_index_out: (
        list[tuple[dict[int, tuple[_JsonObject | _JsonArray, int]], int]] | None
    ) = None,
    _skip_trigger_check: bool = False,
    _step0_possible_out: list[bool] | None = None,
) -> tuple[str, int]:
    if depth > _MAX_NESTED_REDACT_DEPTH:
        raise MemoryValidationError("Memory text exceeds maximum JSON nesting depth.")

    count = 0

    def _replace_pem(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"redacted {len(match.group(0))} chars"

    work = _PEM_KEY_RE.sub(_replace_pem, text) if "-----BEGIN" in text else text
    if not _skip_trigger_check and not _may_have_redact_trigger(work):
        return work, count

    n = len(work)
    has_kv = ":" in work or "=" in work
    has_auth = ("b" in work or "B" in work) and n >= 6
    has_url = "://" in work and "@" in work
    has_json = "{" in work or "[" in work

    pos = 0
    emit_pos = 0
    parts: list[str] = []

    kv_cand: _KvMatch | None = None
    auth_cand: re.Match[str] | None = None
    auth_from = -1
    url_cand: re.Match[str] | None = None
    url_from = -1
    min_json_trigger = _earliest_redact_trigger(work) if has_json else n
    span_end, needed_desc = (
        _build_json_bounds(work, min_needed_end=min_json_trigger) if has_json else ({}, [])
    )
    needed_desc.reverse()
    json_keys = needed_desc
    json_ki = 0
    json_len = len(json_keys)
    ast_memo: dict[int, tuple[_JsonObject | _JsonArray, int]] = {}
    ast_depths: dict[int, int] = {}
    bal_cache: dict[int, int | None] = {}
    q_tracker = _QuoteEnclosureTracker(work)
    step0_flag: list[bool] | None = [False] if _step0_possible_out is not None else None
    json_ast_cache: dict[str, tuple[str, int, bool]] = {}

    while pos < n and (has_kv or has_auth or has_url or json_ki < json_len):
        while json_ki < json_len and json_keys[json_ki] < pos:
            json_ki += 1
        json_cand: tuple[int, int] | None = None
        if json_ki < json_len:
            jk = json_keys[json_ki]
            json_cand = (jk, span_end[jk])

        if has_kv and (kv_cand is None or kv_cand.anchor < pos):
            if json_cand is not None:
                jpos_lim = json_cand[0]
                if pos < jpos_lim and (":" in work[pos:jpos_lim] or "=" in work[pos:jpos_lim]):
                    kv_cand = _search_valid_kv(work, pos, limit=jpos_lim)
                else:
                    kv_cand = None
            else:
                kv_cand = _search_valid_kv(work, pos)
                if kv_cand is None:
                    has_kv = False
        if has_auth and (auth_from == -1 or (auth_cand is not None and auth_cand.start() < pos)):
            auth_cand = _AUTH_SCHEME_RE.search(work, pos)
            auth_from = pos
            if auth_cand is None:
                has_auth = False
        if has_url and (url_from == -1 or (url_cand is not None and url_cand.start() < pos)):
            url_cand = _search_url_userinfo(work, pos)
            url_from = pos
            if url_cand is None:
                has_url = False

        # Pick earliest candidate by (start_pos, priority): kv(0) < auth(1) < url(2) < json(3)
        best_kind = ""
        best_pos = n + 1
        best_prio = 99
        if kv_cand is not None:
            best_kind, best_pos, best_prio = "kv", kv_cand.anchor, 0
        if auth_cand is not None:
            apos = auth_cand.start()
            if apos < best_pos or (apos == best_pos and best_prio > 1):
                best_kind, best_pos, best_prio = "auth", apos, 1
        if url_cand is not None:
            upos = url_cand.start()
            if upos < best_pos or (upos == best_pos and best_prio > 2):
                best_kind, best_pos, best_prio = "url", upos, 2
        if json_cand is not None:
            jpos = json_cand[0]
            if jpos < best_pos or (jpos == best_pos and best_prio > 3):
                best_kind, best_pos, best_prio = "json", jpos, 3

        if not best_kind:
            break

        if best_kind == "kv":
            assert kv_cand is not None
            kv_res = _scrub_kv_value_at(
                work,
                kv_cand,
                depth,
                tracker=q_tracker,
                json_bounds=span_end,
                bal_cache=bal_cache,
            )
            if kv_res is not None:
                repl, end_idx, sub_c = kv_res
                if sub_c > 0:
                    parts.append(work[emit_pos : kv_cand.val_start])
                    parts.append(repl)
                    count += sub_c
                    emit_pos = end_idx
                if step0_flag is not None and not step0_flag[0] and (
                    work[kv_cand.val_start] in "{["
                ):
                    step0_flag[0] = True
                pos = end_idx
            else:
                if (
                    step0_flag is not None
                    and not step0_flag[0]
                    and kv_cand.val_start < n
                    and work[kv_cand.val_start] in "{["
                ):
                    step0_flag[0] = True
                pos = kv_cand.match_end
        elif best_kind == "auth":
            assert auth_cand is not None
            auth_info = _enclosing_quote_info(work, auth_cand.start(), tracker=q_tracker)
            if auth_info is not None:
                auth_q_prefix, auth_outer_stack = auth_info
                allow_q = True
                pos_q = auth_cand.start()
                while pos_q > 0 and work[pos_q - 1] in "([{":
                    pos_q -= 1
                auth_stack: tuple[tuple[str, int, int], ...] = (
                    *auth_outer_stack,
                    (auth_q_prefix[-1], len(auth_q_prefix) - 1, pos_q - 1),
                )
            else:
                auth_q_prefix = None
                auth_outer_stack = ()
                allow_q = False
                if auth_cand.end() < n and work[auth_cand.end()] == "\\":
                    auth_stack = q_tracker.stack_at(auth_cand.start())
                else:
                    auth_stack = ()
            auth_res = _scrub_auth_value_at(
                work,
                auth_cand.end(),
                enclosing_anchor=auth_cand.start(),
                allow_quoted_enclosure=allow_q,
                depth=depth,
                enclosing_stack=auth_stack,
                enclosing_q_prefix=auth_q_prefix,
                enclosing_outer_stack=auth_outer_stack,
                tracker=q_tracker,
                bal_cache=bal_cache,
            )
            if auth_res is not None:
                repl, end_idx, sub_c = auth_res
                parts.append(work[emit_pos : auth_cand.start()])
                parts.append(f"{auth_cand.group('scheme')} {repl}")
                count += sub_c
                emit_pos = end_idx
                pos = end_idx
            else:
                pos = auth_cand.end()
        elif best_kind == "url":
            assert url_cand is not None
            scheme = url_cand.group(1)
            user = url_cand.group(2)
            pwd = url_cand.group(3)
            colon_only = url_cand.group(4)
            if colon_only is not None:
                if not _is_already_redacted_placeholder(colon_only):
                    parts.append(work[emit_pos : url_cand.start()])
                    count += 1
                    parts.append(f"{scheme}:redacted {len(colon_only)} chars@")
                    emit_pos = url_cand.end()
            else:
                assert user is not None
                user_done = _is_already_redacted_placeholder(user)
                pwd_done = pwd is None or _is_already_redacted_placeholder(pwd)
                if not (user_done and pwd_done):
                    parts.append(work[emit_pos : url_cand.start()])
                    count += 1
                    safe_user = user if user_done else f"redacted {len(user)} chars"
                    if pwd is not None:
                        safe_pwd = pwd if pwd_done else f"redacted {len(pwd)} chars"
                        parts.append(f"{scheme}{safe_user}:{safe_pwd}@")
                    else:
                        parts.append(f"{scheme}{safe_user}@")
                    emit_pos = url_cand.end()
            pos = url_cand.end()
        else:
            assert json_cand is not None
            jpos, jend = json_cand
            if jend > min_json_trigger:
                if jend - jpos <= 256:
                    raw_j = work[jpos:jend]
                    cached_j = json_ast_cache.get(raw_j)
                    if cached_j is not None:
                        scrubbed_json, sub_c, trig_s0 = cached_j
                        if sub_c > 0:
                            parts.append(work[emit_pos:jpos])
                            parts.append(scrubbed_json)
                            count += sub_c
                            emit_pos = jend
                        if trig_s0 and step0_flag is not None:
                            step0_flag[0] = True
                    elif _may_have_redact_trigger(raw_j):
                        parsed_j = _parse_json_span(
                            work,
                            jpos,
                            _MAX_JSON_AST_DEPTH,
                            _memo=ast_memo,
                            _memo_depths=ast_depths,
                        )
                        if parsed_j is not None:
                            local_s0 = [False] if step0_flag is not None else None
                            scrubbed_json, sub_c = _redact_json_ast(
                                work, parsed_j[0], depth, step0_flag=local_s0
                            )
                            trig_s0 = local_s0[0] if local_s0 is not None else False
                            if len(json_ast_cache) < 1024:
                                json_ast_cache[raw_j] = (scrubbed_json, sub_c, trig_s0)
                            if sub_c > 0:
                                parts.append(work[emit_pos:jpos])
                                parts.append(scrubbed_json)
                                count += sub_c
                                emit_pos = jend
                            if trig_s0 and step0_flag is not None:
                                step0_flag[0] = True
                    else:
                        trig_s0 = step0_flag is not None and _may_normalize_probe(raw_j)
                        if len(json_ast_cache) < 1024:
                            json_ast_cache[raw_j] = (raw_j, 0, trig_s0)
                        if trig_s0 and step0_flag is not None:
                            step0_flag[0] = True
                elif _may_have_redact_trigger(work[jpos:jend]):
                    parsed_j = _parse_json_span(
                        work,
                        jpos,
                        _MAX_JSON_AST_DEPTH,
                        _memo=ast_memo,
                        _memo_depths=ast_depths,
                    )
                    if parsed_j is not None:
                        scrubbed_json, sub_c = _redact_json_ast(
                            work, parsed_j[0], depth, step0_flag=step0_flag
                        )
                        if sub_c > 0:
                            parts.append(work[emit_pos:jpos])
                            parts.append(scrubbed_json)
                            count += sub_c
                            emit_pos = jend
                elif (
                    step0_flag is not None
                    and not step0_flag[0]
                    and _may_normalize_probe(work[jpos:jend])
                ):
                    step0_flag[0] = True
            pos = jend

    if (
        _json_index_out is not None
        and (step0_flag is None or step0_flag[0])
        and ast_memo
        and len(ast_memo) == len(json_keys)
    ):
        _json_index_out.append((ast_memo, min_json_trigger))

    if parts:
        if emit_pos < n:
            parts.append(work[emit_pos:])
        scrubbed = "".join(parts)
    else:
        scrubbed = work

    def _replace_token(match: re.Match[str]) -> str:
        nonlocal count
        tok = match.group(0)
        count += 1
        return f"redacted {len(tok)} chars"

    if len(scrubbed) >= 10 and (
        "sk-" in scrubbed
        or "gh" in scrubbed
        or "xox" in scrubbed
        or "AKIA" in scrubbed
        or "AIza" in scrubbed
        or "eyJ" in scrubbed
    ):
        scrubbed = _TOKEN_PREFIX_RE.sub(_replace_token, scrubbed)
    if _step0_possible_out is not None and step0_flag is not None:
        _step0_possible_out.append(step0_flag[0])
    return scrubbed, count


def _is_re_word_char(ch: str) -> bool:
    if ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9"):
        return True
    if ord(ch) < 128:
        return False
    return _WORD_CHAR_RE.match(ch) is not None


def _is_alnum_ascii(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")


def _fast_contains_unredacted_secret_strict(probe: str) -> bool:
    normalized = (
        _REDACTED_AUTH_PUNCT_RE.sub(r"\1 [REDACTED] ", probe)
        if ("[REDACTED]" in probe and ("b" in probe or "B" in probe))
        else probe
    )
    n = len(normalized)

    if "b" in normalized or "B" in normalized:
        pos = 0
        while pos < n:
            am = _AUTH_SCHEME_RE.search(normalized, pos)
            if am is None:
                break
            v = am.end()
            if v < n:
                if not normalized.startswith("[REDACTED]", v):
                    return True
                after = v + 10
                if after < n and not normalized[after].isspace():
                    return True
            pos = v

    if "@" in normalized and "://" in normalized:
        pos = 0
        while True:
            sep = normalized.find("://", pos)
            if sep == -1:
                break
            s = sep
            while s > 0 and normalized[s - 1] in _URL_SCHEME_CHARS:
                s -= 1
            while s < sep and not ("a" <= normalized[s] <= "z" or "A" <= normalized[s] <= "Z"):
                s += 1
            if s < sep:
                m = _URL_USERINFO_RE.match(normalized, s)
                if m is not None:
                    colon_only = m.group(4)
                    if colon_only is not None:
                        if colon_only != "[REDACTED]":
                            return True
                    else:
                        user = m.group(2)
                        pwd = m.group(3)
                        if not (user == "[REDACTED]" and (pwd is None or pwd == "[REDACTED]")):
                            return True
            pos = sep + 3

    if "=" in normalized:
        pos = 0
        while True:
            eq_idx = normalized.find("=", pos)
            if eq_idx == -1:
                break
            pos = eq_idx + 1
            if eq_idx == 0 or normalized[eq_idx - 1] not in _SENSITIVE_KEY_END_CHARS:
                continue
            v = eq_idx + 1
            if v >= n or normalized[v].isspace() or normalized[v] in "&;,'\"":
                continue
            if normalized.startswith("[REDACTED]", v):
                after = v + 10
                if after == n or normalized[after].isspace() or normalized[after] in "&;,'\"":
                    continue

            if _QUERY_BRANCH3_RE.search(normalized[max(0, eq_idx - 14) : eq_idx]) is not None:
                return True

            sub1_start = max(0, eq_idx - 13)
            m1 = _QUERY_BRANCH1_SUFFIX_RE.search(normalized[sub1_start:eq_idx])
            if m1 is not None:
                sep_pos = sub1_start + m1.start()
                found_boundary = False
                last_is_w = normalized[sep_pos] == "_"
                j = sep_pos
                while j > 0 and normalized[j - 1] in _KV_KEY_CHARS:
                    j -= 1
                    cur_is_w = normalized[j] not in ".-"
                    if cur_is_w != last_is_w:
                        found_boundary = True
                        break
                    last_is_w = cur_is_w
                if found_boundary:
                    return True
                prev_is_w = j > 0 and _is_re_word_char(normalized[j - 1])
                if prev_is_w != last_is_w:
                    return True

            sub2_start = max(0, eq_idx - 11)
            m2 = _QUERY_BRANCH2_SUFFIX_RE.search(normalized[sub2_start:eq_idx])
            if m2 is not None:
                sfx_pos = sub2_start + m2.start()
                j = sfx_pos
                while j > 0 and _is_alnum_ascii(normalized[j - 1]):
                    j -= 1
                if (
                    j < sfx_pos
                    and ("a" <= normalized[j] <= "z" or "0" <= normalized[j] <= "9")
                    and (j == 0 or not _is_re_word_char(normalized[j - 1]))
                ):
                    return True

    return False


def _probe_json_container_is_clean(obj: Any, depth: int = 0) -> bool:
    if depth > _MAX_NESTED_REDACT_DEPTH:
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                return False
            if k:
                norm_k = _normalize_probe(k, depth + 1)
                if _fast_contains_unredacted_secret_strict(norm_k):
                    return False
            if not _probe_json_container_is_clean(v, depth + 1):
                return False
        return True
    if isinstance(obj, list):
        return all(_probe_json_container_is_clean(item, depth + 1) for item in obj)
    if isinstance(obj, str):
        return (
            obj == ""
            or obj == "[REDACTED]"
            or bool(_PROBE_REDACTED_AUTH_STR_RE.fullmatch(obj.strip()))
        )
    return obj is None


def _may_normalize_probe(text: str) -> bool:
    return (
        "redacted " in text
        or "[REDACTED]" in text
        or "=" in text
        or ("\\" in text and ("{" in text or "[" in text))
    )


def _may_normalize_leaf(text: str) -> bool:
    if (
        "\\" in text
        or '"' in text
        or "'" in text
        or "{" in text
        or "[REDACTED])" in text
        or "[REDACTED]]" in text
        or "[REDACTED]}" in text
        or ("redacted " in text and (")" in text or "]" in text or "}" in text))
    ):
        return True
    return "[" in text and (
        "[REDACTED]" not in text or text.count("[") > text.count("[REDACTED]")
    )


def _normalize_probe(
    scrubbed: str,
    depth: int = 0,
    *,
    _precomputed_json_index: dict[int, tuple[_JsonObject | _JsonArray, int]] | None = None,
    _precomputed_json_min_end: int = 0,
    _skip_step0: bool = False,
) -> str:
    if not _may_normalize_probe(scrubbed):
        return scrubbed
    has_redacted_phrase = "redacted " in scrubbed
    first_red_pos = scrubbed.find("redacted ") if (depth == 0 and has_redacted_phrase) else -1
    probe = (
        _REDACTED_N_CHARS_RE.sub("[REDACTED]", scrubbed)
        if (depth == 0 and has_redacted_phrase)
        else scrubbed
    )

    json_index0: dict[int, tuple[_JsonObject | _JsonArray, int]] | None = None
    step0_modified = False

    # 0. Normalize clean nested JSON string leaves recursively at any nesting depth
    step0_needed = (
        "=" in probe
        or "\\" in probe
        or "[REDACTED])" in probe
        or "[REDACTED]]" in probe
        or "[REDACTED]}" in probe
        or ("'" in probe and "[REDACTED]" in probe and ("b" in probe or "B" in probe))
        or (depth > 0 and "[REDACTED]\"" in probe and ("b" in probe or "B" in probe))
    )
    if (
        not _skip_step0
        and step0_needed
        and depth <= _MAX_NESTED_REDACT_DEPTH
        and '"' in probe
        and (
            "{" in probe
            or (
                "[" in probe
                and ("[REDACTED]" not in probe or probe.count("[") > probe.count("[REDACTED]"))
            )
        )
    ):
        min_trigger = len(probe)
        for needle in ("=", "\\", "[REDACTED]", "redacted "):
            n_idx = probe.find(needle)
            if n_idx != -1 and n_idx < min_trigger:
                min_trigger = n_idx
        if (
            _precomputed_json_index is not None
            and _precomputed_json_min_end <= min_trigger
            and (
                probe is scrubbed
                or (
                    first_red_pos != -1
                    and all(end <= first_red_pos for _, end in _precomputed_json_index.values())
                )
            )
        ):
            json_index0 = _precomputed_json_index
        else:
            json_index0 = _build_json_span_index(probe, min_needed_end=min_trigger)
        if json_index0:
            emit_cur = 0
            scan_cur = 0
            out0: list[str] = []

            def _collect_probe_leaf_edits(
                node: _JsonNode, leaf_edits: list[tuple[int, int, str]]
            ) -> None:
                kind = node[0]
                if kind == _JSON_OBJ:
                    for k_node, v_node in cast(_JsonObject, node)[3]:
                        k_s, k_e = k_node[1], k_node[2]
                        raw_k_s = probe[k_s:k_e]
                        if "\\" not in raw_k_s:
                            k_val = raw_k_s[1:-1]
                            k_may = _may_normalize_leaf(k_val)
                        else:
                            loaded_k = json.loads(raw_k_s)
                            assert isinstance(loaded_k, str)
                            k_val = loaded_k
                            k_may = bool(k_val) and _may_normalize_leaf(k_val)
                        if k_val:
                            norm_k = _normalize_probe(k_val, depth + 1) if k_may else k_val
                            if depth > 0 and norm_k.endswith("[REDACTED]"):
                                norm_k = norm_k + " "
                            if norm_k != k_val:
                                leaf_edits.append(
                                    (k_s, k_e, json.dumps(norm_k, ensure_ascii=False))
                                )
                        vk = v_node[0]
                        if vk == _JSON_STR:
                            v_s, v_e = v_node[1], v_node[2]
                            raw_v_s = probe[v_s:v_e]
                            if "\\" not in raw_v_s:
                                s_val = raw_v_s[1:-1]
                            else:
                                loaded_v = json.loads(raw_v_s)
                                assert isinstance(loaded_v, str)
                                s_val = loaded_v
                            if s_val:
                                s_may = _may_normalize_leaf(s_val)
                                norm_s = _normalize_probe(s_val, depth + 1) if s_may else s_val
                                if depth > 0 and norm_s.endswith("[REDACTED]"):
                                    norm_s = norm_s + " "
                                if norm_s != s_val:
                                    leaf_edits.append(
                                        (v_s, v_e, json.dumps(norm_s, ensure_ascii=False))
                                    )
                        elif vk != _JSON_SCALAR:
                            _collect_probe_leaf_edits(v_node, leaf_edits)
                elif kind == _JSON_ARR:
                    for item in cast(_JsonArray, node)[3]:
                        ik = item[0]
                        if ik == _JSON_STR:
                            i_s, i_e = item[1], item[2]
                            raw_i_s = probe[i_s:i_e]
                            if "\\" not in raw_i_s:
                                s_val = raw_i_s[1:-1]
                            else:
                                loaded_i = json.loads(raw_i_s)
                                assert isinstance(loaded_i, str)
                                s_val = loaded_i
                            if s_val:
                                s_may = _may_normalize_leaf(s_val)
                                norm_s = _normalize_probe(s_val, depth + 1) if s_may else s_val
                                if depth > 0 and norm_s.endswith("[REDACTED]"):
                                    norm_s = norm_s + " "
                                if norm_s != s_val:
                                    leaf_edits.append(
                                        (i_s, i_e, json.dumps(norm_s, ensure_ascii=False))
                                    )
                        elif ik != _JSON_SCALAR:
                            _collect_probe_leaf_edits(item, leaf_edits)
                elif kind == _JSON_STR:
                    n_s, n_e = node[1], node[2]
                    raw_s_s = probe[n_s:n_e]
                    if "\\" not in raw_s_s:
                        s_val = raw_s_s[1:-1]
                    else:
                        loaded_s = json.loads(raw_s_s)
                        assert isinstance(loaded_s, str)
                        s_val = loaded_s
                    if s_val:
                        s_may = _may_normalize_leaf(s_val)
                        norm_s = _normalize_probe(s_val, depth + 1) if s_may else s_val
                        if depth > 0 and norm_s.endswith("[REDACTED]"):
                            norm_s = norm_s + " "
                        if norm_s != s_val:
                            leaf_edits.append(
                                (n_s, n_e, json.dumps(norm_s, ensure_ascii=False))
                            )

            for jpos in sorted(json_index0):
                if jpos < scan_cur:
                    continue
                jnode, jend = json_index0[jpos]
                if jend > min_trigger and _may_normalize_probe(probe[jpos:jend]):
                    edits: list[tuple[int, int, str]] = []
                    _collect_probe_leaf_edits(jnode, edits)
                    if edits:
                        out0.append(probe[emit_cur:jpos])
                        lcur = jpos
                        for es, ee, erepl in edits:
                            out0.append(probe[lcur:es])
                            out0.append(erepl)
                            lcur = ee
                        out0.append(probe[lcur:jend])
                        emit_cur = jend
                scan_cur = jend
            if out0:
                out0.append(probe[emit_cur:])
                probe = "".join(out0)
                step0_modified = True

    # 1. Normalize clean sensitive key={...} / key=[...] / key="<q>[REDACTED]<q>"
    #    and enclosed <q>key=[REDACTED]<q> before Bearer/Basic quote stripping.
    step1_needed = "=" in probe and (
        "{" in probe
        or '"' in probe
        or "'" in probe
        or (
            "[" in probe
            and ("[REDACTED]" not in probe or probe.count("[") > probe.count("[REDACTED]"))
        )
    )
    if step1_needed:
        n = len(probe)
        out2: list[str] = []
        emit_pos2 = 0
        pos = 0
        json_bounds2: dict[int, int] | None = (
            {jk: jv[1] for jk, jv in json_index0.items()}
            if (not step0_modified and json_index0 is not None)
            else None
        )
        built_json_bounds2 = json_bounds2 is not None
        bal_cache2: dict[int, int | None] = {}
        q_tracker2 = _QuoteEnclosureTracker(probe)
        j0_keys = sorted(json_index0) if (not step0_modified and json_index0) else []
        j0_ki = 0
        j0_len = len(j0_keys)
        while pos < n:
            if j0_ki < j0_len:
                while j0_ki < j0_len and json_index0[j0_keys[j0_ki]][1] <= pos:  # type: ignore[index]
                    j0_ki += 1
                if j0_ki < j0_len:
                    j0_pos = j0_keys[j0_ki]
                    j0_end = json_index0[j0_pos][1]  # type: ignore[index]
                    if pos >= j0_pos:
                        pos = j0_end
                        continue
                    if "=" not in probe[pos:j0_pos]:
                        pos = j0_end
                        continue
                    kv = _search_valid_kv(probe, pos, eq_only=True, limit=j0_pos)
                    if kv is None:
                        pos = j0_end
                        continue
                else:
                    kv = _search_valid_kv(probe, pos, eq_only=True)
            else:
                kv = _search_valid_kv(probe, pos, eq_only=True)
            if kv is None:
                break
            val_start = kv.val_start
            if "=" in kv.sep and val_start < n:
                if (
                    kv.key_bs == 0
                    and probe.startswith("[REDACTED]", val_start)
                    and kv.anchor >= 1
                    and probe[kv.anchor - 1] in "\"'([{"
                ):
                    pos_open = kv.anchor
                    while pos_open > pos and probe[pos_open - 1] in "([{":
                        pos_open -= 1
                    if pos_open > pos and probe[pos_open - 1] in "\"'":
                        qchar = probe[pos_open - 1]
                        bs = _count_leading_backslashes(probe, pos_open - 1)
                        q_prefix = ("\\" * bs) + qchar
                        open_start = pos_open - len(q_prefix)
                        val_end = val_start + 10
                        close_b = val_end
                        while close_b < n and probe[close_b] in ")]}":
                            close_b += 1
                        if (
                            (bs > 0 or close_b > val_end or depth > 0)
                            and open_start >= pos
                            and _is_valid_escape_bs(bs)
                            and probe.startswith(q_prefix, close_b)
                        ):
                            enc_info = _enclosing_quote_info(probe, kv.anchor, tracker=q_tracker2)
                            if enc_info is not None and enc_info[0] == q_prefix:
                                close_end = close_b + len(q_prefix)
                                if _is_clean_redacted_tail_quoted(
                                    probe, close_end, bs, enclosing_stack=enc_info[1]
                                ):
                                    out2.append(probe[emit_pos2:open_start])
                                    out2.append(f"{probe[kv.anchor:val_start]}[REDACTED] ")
                                    emit_pos2 = close_end
                                    pos = close_end
                                    continue
                if probe.startswith("[REDACTED]", val_start):
                    pos = kv.match_end
                    continue
                if probe[val_start] in "{[":
                    if not built_json_bounds2:
                        json_bounds2, _ = _build_json_bounds(probe, min_needed_end=val_start)
                        built_json_bounds2 = True
                    json_end = json_bounds2.get(val_start) if json_bounds2 is not None else None
                    if json_end is not None:
                        if _VALID_STRUCTURED_TAIL_RE.match(probe, json_end) is not None:
                            obj = json.loads(probe[val_start:json_end])
                            if isinstance(
                                obj, (dict, list)
                            ) and _probe_json_container_is_clean(obj, depth + 1):
                                out2.append(probe[emit_pos2:val_start])
                                out2.append("[REDACTED] ")
                                emit_pos2 = json_end
                                pos = json_end
                                continue
                    else:
                        bal_end = _find_balanced_container_end(probe, val_start, cache=bal_cache2)
                        if bal_end is not None:
                            kv_stack = q_tracker2.stack_at(kv.anchor) if kv.key_bs > 0 else ()
                            if (
                                _VALID_STRUCTURED_TAIL_RE.match(probe, bal_end) is not None
                                or (
                                    kv.key_bs > 0
                                    and _VALID_STRUCTURED_TAIL_RE.match(
                                        probe,
                                        _skip_outer_quotes_for_escaped_tail(
                                            probe,
                                            bal_end,
                                            kv.key_bs,
                                            enclosing_stack=kv_stack,
                                        ),
                                    )
                                    is not None
                                )
                            ):
                                raw_c = probe[val_start:bal_end]
                                try:
                                    unescaped = json.loads('"' + raw_c + '"')
                                    obj = (
                                        json.loads(unescaped)
                                        if isinstance(unescaped, str)
                                        else None
                                    )
                                except json.JSONDecodeError:
                                    obj = None
                                if isinstance(
                                    obj, (dict, list)
                                ) and _probe_json_container_is_clean(obj, depth + 1):
                                    out2.append(probe[emit_pos2:val_start])
                                    out2.append("[REDACTED] ")
                                    emit_pos2 = bal_end
                                    pos = bal_end
                                    continue
                elif probe[val_start] in "\"'\\":
                    q_res = _match_quoted_span(probe, val_start)
                    if q_res is not None:
                        closed, inner_start, inner_end, span_end, prefix, _ = q_res
                        bs = len(prefix) - 1
                        if closed and probe[inner_start:inner_end] == "[REDACTED]":
                            kv_stack = q_tracker2.stack_at(kv.anchor) if bs > 0 else ()
                            if _is_clean_redacted_tail_quoted(
                                probe, span_end, bs, enclosing_stack=kv_stack
                            ):
                                out2.append(probe[emit_pos2:val_start])
                                out2.append("[REDACTED] ")
                                emit_pos2 = span_end
                                pos = span_end
                                continue
            pos = kv.match_end
        if out2:
            out2.append(probe[emit_pos2:])
            probe = "".join(out2)

    # 2. Normalize clean quoted Bearer/Basic "[REDACTED]" and enclosed
    #    "<q>(Authorization: )?Bearer/Basic [REDACTED]<q>"
    if "[REDACTED]" in probe and ("b" in probe or "B" in probe):
        n = len(probe)
        out1: list[str] = []
        emit_pos1 = 0
        pos = 0
        q_tracker1 = _QuoteEnclosureTracker(probe)
        while pos < n:
            am = _AUTH_SCHEME_RE.search(probe, pos)
            if am is None:
                break
            if am.end() < n and probe[am.end()] in "\"'\\":
                q_res = _match_quoted_span(probe, am.end())
                if q_res is not None:
                    closed, inner_start, inner_end, span_end, prefix, _ = q_res
                    bs = len(prefix) - 1
                    if closed and probe[inner_start:inner_end] == "[REDACTED]":
                        auth_stack = q_tracker1.stack_at(am.start()) if bs > 0 else ()
                        if _is_clean_redacted_tail_quoted(
                            probe, span_end, bs, enclosing_stack=auth_stack
                        ):
                            out1.append(probe[emit_pos1 : am.start()])
                            out1.append(f"{am.group('scheme')} [REDACTED] ")
                            emit_pos1 = span_end
                            pos = span_end
                            continue
            if probe.startswith("[REDACTED]", am.end()) and am.start() >= 1:
                hdr_m = _AUTH_COLON_PREFIX_RE.search(probe[pos : am.start()])
                cand_starts: tuple[int, ...] = (
                    (pos + hdr_m.start(), am.start()) if hdr_m is not None else (am.start(),)
                )
                matched_enc = False
                for cand_start in cand_starts:
                    pos_open = cand_start
                    while pos_open > pos and probe[pos_open - 1] in "([{":
                        pos_open -= 1
                    if pos_open <= pos or probe[pos_open - 1] not in "\"'":
                        continue
                    qchar = probe[pos_open - 1]
                    bs = _count_leading_backslashes(probe, pos_open - 1)
                    q_prefix = ("\\" * bs) + qchar
                    open_start = pos_open - len(q_prefix)
                    close_b = am.end() + 10
                    while close_b < n and probe[close_b] in ")]}":
                        close_b += 1
                    if (
                        open_start >= pos
                        and _is_valid_escape_bs(bs)
                        and probe.startswith(q_prefix, close_b)
                    ):
                        enc_info = _enclosing_quote_info(probe, cand_start, tracker=q_tracker1)
                        if enc_info is not None and enc_info[0] == q_prefix:
                            close_end = close_b + len(q_prefix)
                            if _is_clean_redacted_tail_quoted(
                                probe, close_end, bs, enclosing_stack=enc_info[1]
                            ):
                                out1.append(probe[emit_pos1:open_start])
                                out1.append(f"{probe[cand_start:am.end()]}[REDACTED] ")
                                emit_pos1 = close_end
                                pos = close_end
                                matched_enc = True
                                break
                if matched_enc:
                    continue
            pos = am.end()
        if out1:
            out1.append(probe[emit_pos1:])
            probe = "".join(out1)

    # 3. Normalize clean [REDACTED] directly before closing brackets
    if "[REDACTED]" in probe and (")" in probe or "]" in probe or "}" in probe):
        probe = _PROBE_TRAILING_BRACKET_RE.sub("[REDACTED] ", probe)
    return probe


def redact_memory_text(text: str) -> tuple[str, int]:
    """Scrub secret material using exact 'redacted N chars' placeholders."""
    idx_out: list[tuple[dict[int, tuple[_JsonObject | _JsonArray, int]], int]] = []
    step0_possible: list[bool] = []
    scrubbed, count = _redact_core(
        text, 0, _json_index_out=idx_out, _step0_possible_out=step0_possible
    )
    pre_idx: dict[int, tuple[_JsonObject | _JsonArray, int]] | None = None
    pre_min_end = 0
    if idx_out:
        cand_idx, cand_min_end = idx_out[0]
        if scrubbed is text:
            pre_idx = cand_idx
            pre_min_end = cand_min_end
        else:
            first_red = scrubbed.find("redacted ")
            if first_red != -1 and all(end <= first_red for _, end in cand_idx.values()):
                pre_idx = cand_idx
                pre_min_end = cand_min_end
    skip_step0 = bool(step0_possible) and not step0_possible[0]
    probe = _normalize_probe(
        scrubbed,
        _precomputed_json_index=pre_idx,
        _precomputed_json_min_end=pre_min_end,
        _skip_step0=skip_step0,
    )
    if _fast_contains_unredacted_secret_strict(probe):
        raise MemoryValidationError("Memory text contains unredacted secret material.")
    return scrubbed, count


class MemoryStore:
    """Compartmentalized SQLite FTS5 memory store with SQL ACLs, TTL, and optimistic locking."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        lock: threading.RLock | None = None,
        audit_fn: Callable[..., Any] | None = None,
    ) -> None:
        self._is_memory = str(db_path) == ":memory:"
        self._db_path = Path(str(db_path)) if not self._is_memory else Path(":memory:")
        self._lock = lock or threading.RLock()
        self._audit_fn = audit_fn
        self._mem_conn: sqlite3.Connection | None = None

        if self._is_memory:
            self._mem_conn = sqlite3.connect(
                ":memory:",
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys=ON;")
            self._mem_conn.execute("PRAGMA busy_timeout=5000;")
            self._mem_conn.execute("PRAGMA synchronous=NORMAL;")

        self._init_schema()

    def close(self) -> None:
        with self._lock:
            if self._mem_conn is not None:
                self._mem_conn.close()
                self._mem_conn = None

    @contextlib.contextmanager
    def _write_tx(self) -> Iterator[sqlite3.Connection]:
        if self._is_memory:
            with self._lock:
                assert self._mem_conn is not None
                self._mem_conn.execute("BEGIN IMMEDIATE;")
                try:
                    yield self._mem_conn
                    self._mem_conn.execute("COMMIT;")
                except BaseException:
                    if self._mem_conn.in_transaction:
                        self._mem_conn.execute("ROLLBACK;")
                    raise
            return

        with write_transaction(self._db_path, self._lock) as conn:
            yield conn

    @contextlib.contextmanager
    def _read_tx(self) -> Iterator[sqlite3.Connection]:
        if self._is_memory:
            with self._lock:
                assert self._mem_conn is not None
                yield self._mem_conn
            return

        with read_transaction(self._db_path) as conn:
            yield conn

    def _init_schema(self) -> None:
        stmts = (
            """
            CREATE TABLE IF NOT EXISTS memory_items (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT UNIQUE NOT NULL,
                scope TEXT NOT NULL CHECK (
                    scope IN ('user', 'agent_role', 'thread', 'project_area', 'org_approved')
                ),
                scope_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (
                    kind IN (
                        'preference',
                        'approved_procedure',
                        'dated_observation',
                        'source_reference'
                    )
                ),
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '',
                observed_at TEXT,
                valid_until TEXT,
                provenance TEXT NOT NULL DEFAULT 'operator',
                created_by TEXT NOT NULL DEFAULT 'operator',
                created_by_role TEXT NOT NULL DEFAULT 'Operator',
                revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_memory_items_scope
                ON memory_items(scope, scope_id, kind)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_memory_items_valid
                ON memory_items(kind, valid_until, updated_at)
            """,
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                title,
                content,
                tags,
                content='memory_items',
                content_rowid='seq',
                tokenize="unicode61 tokenchars '-_/'"
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS trg_memory_items_ai AFTER INSERT ON memory_items BEGIN
                INSERT INTO memory_fts(rowid, title, content, tags)
                VALUES (new.seq, new.title, new.content, new.tags);
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS trg_memory_items_ad AFTER DELETE ON memory_items BEGIN
                INSERT INTO memory_fts(memory_fts, rowid, title, content, tags)
                VALUES ('delete', old.seq, old.title, old.content, old.tags);
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS trg_memory_items_au AFTER UPDATE ON memory_items BEGIN
                INSERT INTO memory_fts(memory_fts, rowid, title, content, tags)
                VALUES ('delete', old.seq, old.title, old.content, old.tags);
                INSERT INTO memory_fts(rowid, title, content, tags)
                VALUES (new.seq, new.title, new.content, new.tags);
            END
            """,
        )
        with self._write_tx() as conn:
            for stmt in stmts:
                conn.execute(stmt)

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "scope": str(row["scope"]),
            "scope_id": str(row["scope_id"]),
            "kind": str(row["kind"]),
            "title": str(row["title"]),
            "content": str(row["content"]),
            "tags": str(row["tags"]),
            "observed_at": row["observed_at"],
            "valid_until": row["valid_until"],
            "provenance": str(row["provenance"]),
            "created_by": str(row["created_by"]),
            "created_by_role": str(row["created_by_role"]),
            "revision": int(row["revision"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _build_acl_where(
        ctx: MemoryAccessContext,
        *,
        table_alias: str = "",
    ) -> tuple[str, list[Any]]:
        prefix = f"{table_alias}." if table_alias else ""
        clauses: list[str] = []
        params: list[Any] = []
        if ctx.include_org_approved:
            clauses.append(f"{prefix}scope = 'org_approved'")
        if ctx.user_id:
            clauses.append(f"({prefix}scope = 'user' AND {prefix}scope_id = ?)")
            params.append(ctx.user_id)
        if ctx.agent_role:
            clauses.append(f"({prefix}scope = 'agent_role' AND {prefix}scope_id = ?)")
            params.append(ctx.agent_role)
        if ctx.thread_id:
            clauses.append(f"({prefix}scope = 'thread' AND {prefix}scope_id = ?)")
            params.append(ctx.thread_id)
        if ctx.project_area:
            clauses.append(f"({prefix}scope = 'project_area' AND {prefix}scope_id = ?)")
            params.append(ctx.project_area)
        if not clauses:
            return "1 = 0", []
        return "(" + " OR ".join(clauses) + ")", params

    @staticmethod
    def _is_item_accessible(row: sqlite3.Row, ctx: MemoryAccessContext) -> bool:
        scope = str(row["scope"])
        scope_id = str(row["scope_id"])
        if scope == "org_approved":
            return ctx.include_org_approved
        if scope == "user":
            return bool(ctx.user_id) and scope_id == ctx.user_id
        if scope == "agent_role":
            return bool(ctx.agent_role) and scope_id == ctx.agent_role
        if scope == "thread":
            return bool(ctx.thread_id) and scope_id == ctx.thread_id
        if scope == "project_area":
            return bool(ctx.project_area) and scope_id == ctx.project_area
        return False

    def _emit_audit(
        self,
        conn: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        entity_id: str | None,
        decision: str,
        detail: dict[str, Any],
    ) -> None:
        if self._audit_fn is None:
            return
        self._audit_fn(
            conn,
            actor=actor,
            action=action,
            entity_type="memory_item",
            entity_id=entity_id,
            decision=decision,
            detail=detail,
        )

    def create_memory(
        self,
        *,
        scope: str,
        scope_id: str,
        kind: str,
        title: str,
        content: str,
        tags: str = "",
        observed_at: str | None = None,
        valid_until: str | None = None,
        provenance: str = "operator",
        actor_role: str = "Operator",
        created_by: str = "operator",
    ) -> dict[str, Any]:
        norm_scope = normalize_scope(scope)
        norm_kind = normalize_kind(kind)
        cleaned_scope_id = scope_id.strip()
        if not cleaned_scope_id:
            raise MemoryValidationError("scope_id must not be empty.")
        cleaned_title = title.strip()
        if not cleaned_title:
            raise MemoryValidationError("title must not be empty.")
        cleaned_content = content.strip()
        if not cleaned_content:
            raise MemoryValidationError("content must not be empty.")
        norm_provenance = (provenance or "operator").strip().lower() or "operator"
        norm_role = (actor_role or "Operator").strip() or "Operator"
        norm_actor = (created_by or "operator").strip() or "operator"

        if norm_kind == "approved_procedure":
            if norm_provenance == "untrusted":
                if self._audit_fn is not None:
                    with self._write_tx() as conn:
                        self._emit_audit(
                            conn,
                            actor=norm_actor,
                            action="memory.promote_denied",
                            entity_id=None,
                            decision="deny",
                            detail={"reason": "untrusted_provenance", "scope": norm_scope},
                        )
                raise MemoryPermissionError(
                    "Untrusted provenance cannot be promoted to approved_procedure."
                )
            if norm_role.lower() != "manager":
                if self._audit_fn is not None:
                    with self._write_tx() as conn:
                        self._emit_audit(
                            conn,
                            actor=norm_actor,
                            action="memory.promote_denied",
                            entity_id=None,
                            decision="deny",
                            detail={"reason": "non_manager_role", "actor_role": norm_role},
                        )
                raise MemoryPermissionError(
                    "Only Manager role can write or edit approved_procedure memories."
                )
        if norm_scope == "org_approved" and norm_role.lower() != "manager":
            if self._audit_fn is not None:
                with self._write_tx() as conn:
                    self._emit_audit(
                        conn,
                        actor=norm_actor,
                        action="memory.promote_denied",
                        entity_id=None,
                        decision="deny",
                        detail={
                            "reason": "non_manager_role",
                            "scope": norm_scope,
                            "actor_role": norm_role,
                        },
                    )
            raise MemoryPermissionError(
                "Only Manager role can write or edit org_approved memories."
            )

        norm_observed = normalize_iso_timestamp(observed_at, "observed_at")
        norm_valid_until = normalize_iso_timestamp(valid_until, "valid_until")
        if norm_kind == "dated_observation" and (
            norm_observed is None or norm_valid_until is None
        ):
            raise MemoryValidationError(
                "dated_observation requires both valid ISO-8601 observed_at and valid_until."
            )

        safe_title, title_redactions = redact_memory_text(cleaned_title)
        safe_content, content_redactions = redact_memory_text(cleaned_content)
        safe_tags, tags_redactions = redact_memory_text(tags.strip())

        item_id = f"mem_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        with self._write_tx() as conn:
            conn.execute(
                """
                INSERT INTO memory_items (
                    id, scope, scope_id, kind, title, content, tags,
                    observed_at, valid_until, provenance, created_by, created_by_role,
                    revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    item_id,
                    norm_scope,
                    cleaned_scope_id,
                    norm_kind,
                    safe_title,
                    safe_content,
                    safe_tags,
                    norm_observed,
                    norm_valid_until,
                    norm_provenance,
                    norm_actor,
                    norm_role,
                    now,
                    now,
                ),
            )
            self._emit_audit(
                conn,
                actor=norm_actor,
                action="memory.create",
                entity_id=item_id,
                decision="allow",
                detail={
                    "scope": norm_scope,
                    "scope_id": cleaned_scope_id,
                    "kind": norm_kind,
                    "redacted_count": title_redactions + content_redactions + tags_redactions,
                },
            )
            row = conn.execute("SELECT * FROM memory_items WHERE id = ?", (item_id,)).fetchone()
            assert row is not None
            return self._row_to_item(row)

    def get_memory(
        self,
        item_id: str,
        *,
        access_ctx: MemoryAccessContext,
        include_expired: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        acl_sql, acl_params = self._build_acl_where(access_ctx)
        clauses = ["id = ?", acl_sql]
        params: list[Any] = [item_id, *acl_params]
        if not include_expired:
            now_iso = (now or datetime.now(tz=UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            clauses.append("(valid_until IS NULL OR valid_until >= ?)")
            params.append(now_iso)
        sql = f"SELECT * FROM memory_items WHERE {' AND '.join(clauses)}"
        with self._read_tx() as conn:
            row = conn.execute(sql, params).fetchone()
            return self._row_to_item(row) if row is not None else None

    def list_memories(
        self,
        access_ctx: MemoryAccessContext,
        *,
        scope: str | None = None,
        scope_id: str | None = None,
        kind: str | None = None,
        query: str = "",
        include_expired: bool = False,
        limit: int = 100,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 500))
        norm_scope = normalize_scope(scope) if scope else None
        norm_kind = normalize_kind(kind) if kind else None
        fts_query = build_fts5_query(query, operator="AND") if query.strip() else None

        alias = "m" if fts_query is not None else ""
        prefix = "m." if fts_query is not None else ""
        acl_sql, acl_params = self._build_acl_where(access_ctx, table_alias=alias)
        clauses = [acl_sql]
        params: list[Any] = [*acl_params]

        if norm_scope is not None:
            clauses.append(f"{prefix}scope = ?")
            params.append(norm_scope)
        if scope_id is not None and scope_id.strip():
            clauses.append(f"{prefix}scope_id = ?")
            params.append(scope_id.strip())
        if norm_kind is not None:
            clauses.append(f"{prefix}kind = ?")
            params.append(norm_kind)
        if not include_expired:
            now_iso = (now or datetime.now(tz=UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            clauses.append(f"({prefix}valid_until IS NULL OR {prefix}valid_until >= ?)")
            params.append(now_iso)

        if fts_query is not None:
            sql = (
                "SELECT m.* FROM memory_fts "
                "JOIN memory_items m ON m.seq = memory_fts.rowid "
                f"WHERE memory_fts MATCH ? AND {' AND '.join(clauses)} "
                "ORDER BY bm25(memory_fts) ASC, m.updated_at DESC, m.seq DESC "
                "LIMIT ?"
            )
            full_params: list[Any] = [fts_query, *params, bounded]
        else:
            if query.strip():
                # Query had only punctuation/symbols — safe empty result rather than table scan
                return []
            sql = (
                f"SELECT * FROM memory_items WHERE {' AND '.join(clauses)} "
                "ORDER BY updated_at DESC, seq DESC LIMIT ?"
            )
            full_params = [*params, bounded]

        with self._read_tx() as conn:
            rows = conn.execute(sql, full_params).fetchall()
            return [self._row_to_item(r) for r in rows]

    def search_memories(
        self,
        access_ctx: MemoryAccessContext,
        query: str,
        *,
        kind: str | None = None,
        include_expired: bool = False,
        limit: int = 20,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        return self.list_memories(
            access_ctx,
            kind=kind,
            query=query,
            include_expired=include_expired,
            limit=limit,
            now=now,
        )

    def update_memory(
        self,
        item_id: str,
        *,
        expected_revision: int,
        access_ctx: MemoryAccessContext,
        title: str | None = None,
        content: str | None = None,
        tags: str | None = None,
        observed_at: str | None = None,
        valid_until: str | None = None,
        provenance: str | None = None,
        actor_role: str | None = None,
    ) -> dict[str, Any]:
        if expected_revision < 1:
            raise MemoryValidationError("expected_revision must be >= 1.")

        effective_role = (actor_role or access_ctx.actor_role or "Operator").strip() or "Operator"

        with self._write_tx() as conn:
            existing = conn.execute(
                "SELECT * FROM memory_items WHERE id = ?", (item_id,)
            ).fetchone()
            if existing is None:
                raise MemoryNotFoundError(f"Memory item not found: {item_id}")
            if not self._is_item_accessible(existing, access_ctx):
                raise MemoryPermissionError(f"Access denied for memory item: {item_id}")

            existing_scope = str(existing["scope"])
            existing_kind = str(existing["kind"])
            if existing_kind == "approved_procedure":
                if effective_role.lower() != "manager":
                    raise MemoryPermissionError(
                        "Only Manager role can edit approved_procedure memories."
                    )
                if provenance is not None and provenance.strip().lower() == "untrusted":
                    raise MemoryPermissionError(
                        "Untrusted provenance cannot be promoted to approved_procedure."
                    )
            if existing_scope == "org_approved" and effective_role.lower() != "manager":
                raise MemoryPermissionError(
                    "Only Manager role can edit org_approved memories."
                )

            new_title = str(existing["title"])
            new_content = str(existing["content"])
            new_tags = str(existing["tags"])
            redaction_count = 0

            if title is not None:
                cleaned_title = title.strip()
                if not cleaned_title:
                    raise MemoryValidationError("title must not be empty.")
                new_title, r_title = redact_memory_text(cleaned_title)
                redaction_count += r_title
            if content is not None:
                cleaned_content = content.strip()
                if not cleaned_content:
                    raise MemoryValidationError("content must not be empty.")
                new_content, r_content = redact_memory_text(cleaned_content)
                redaction_count += r_content
            if tags is not None:
                new_tags, r_tags = redact_memory_text(tags.strip())
                redaction_count += r_tags

            new_observed = (
                normalize_iso_timestamp(observed_at, "observed_at")
                if observed_at is not None
                else existing["observed_at"]
            )
            new_valid = (
                normalize_iso_timestamp(valid_until, "valid_until")
                if valid_until is not None
                else existing["valid_until"]
            )
            if existing_kind == "dated_observation" and (
                new_observed is None or new_valid is None
            ):
                raise MemoryValidationError(
                    "dated_observation requires valid observed_at and valid_until."
                )

            new_provenance = (
                provenance.strip().lower()
                if provenance is not None and provenance.strip()
                else str(existing["provenance"])
            )
            now = utc_iso_now()
            cur = conn.execute(
                """
                UPDATE memory_items
                SET title = ?, content = ?, tags = ?, observed_at = ?, valid_until = ?,
                    provenance = ?, revision = revision + 1, updated_at = ?
                WHERE id = ? AND revision = ?
                """,
                (
                    new_title,
                    new_content,
                    new_tags,
                    new_observed,
                    new_valid,
                    new_provenance,
                    now,
                    item_id,
                    expected_revision,
                ),
            )
            if cur.rowcount == 0:
                raise MemoryConflictError(
                    f"Revision conflict for memory item {item_id} "
                    f"(expected revision {expected_revision})."
                )

            self._emit_audit(
                conn,
                actor=access_ctx.user_id or effective_role,
                action="memory.update",
                entity_id=item_id,
                decision="allow",
                detail={
                    "expected_revision": expected_revision,
                    "new_revision": expected_revision + 1,
                    "redacted_count": redaction_count,
                },
            )
            updated = conn.execute(
                "SELECT * FROM memory_items WHERE id = ?", (item_id,)
            ).fetchone()
            assert updated is not None
            return self._row_to_item(updated)

    def delete_memory(
        self,
        item_id: str,
        *,
        access_ctx: MemoryAccessContext | None = None,
        actor_role: str | None = None,
    ) -> bool:
        effective_role = (
            actor_role or (access_ctx.actor_role if access_ctx is not None else "Operator")
        ).strip() or "Operator"

        with self._write_tx() as conn:
            existing = conn.execute(
                "SELECT * FROM memory_items WHERE id = ?", (item_id,)
            ).fetchone()
            if existing is None:
                raise MemoryNotFoundError(f"Memory item not found: {item_id}")
            if access_ctx is not None and not self._is_item_accessible(existing, access_ctx):
                raise MemoryPermissionError(f"Access denied for memory item: {item_id}")
            if (
                str(existing["kind"]) == "approved_procedure"
                and effective_role.lower() != "manager"
            ):
                raise MemoryPermissionError(
                    "Only Manager role can delete approved_procedure memories."
                )
            if (
                str(existing["scope"]) == "org_approved"
                and effective_role.lower() != "manager"
            ):
                raise MemoryPermissionError(
                    "Only Manager role can delete org_approved memories."
                )

            seq_id = int(existing["seq"])
            conn.execute("DELETE FROM memory_items WHERE id = ?", (item_id,))

            still_item = conn.execute(
                "SELECT 1 FROM memory_items WHERE id = ?", (item_id,)
            ).fetchone()
            still_fts = conn.execute(
                "SELECT 1 FROM memory_fts_docsize WHERE id = ?", (seq_id,)
            ).fetchone()
            if still_item is not None or still_fts is not None:
                raise MemoryError(f"Failed to purge FTS5 index for deleted memory {item_id}.")

            self._emit_audit(
                conn,
                actor=(access_ctx.user_id if access_ctx and access_ctx.user_id else effective_role),
                action="memory.delete",
                entity_id=item_id,
                decision="allow",
                detail={"kind": str(existing["kind"]), "scope": str(existing["scope"])},
            )
            return True

    @staticmethod
    def _format_memory_block(row: sqlite3.Row) -> str:
        observed = str(row["observed_at"] or "n/a")
        valid_until = str(row["valid_until"] or "none")
        return (
            f"[MEMORY id={row['id']} kind={row['kind']} "
            f"observed_at={observed} valid_until={valid_until} "
            f"authority=advisory_only]\n"
            f"{row['title']}: {row['content']}"
        )

    def build_context_injection(
        self,
        access_ctx: MemoryAccessContext,
        *,
        query: str = "",
        thread_passages: Sequence[str] = (),
        now: datetime | None = None,
    ) -> MemoryContextBundle:
        """Build bounded advisory_only pinned + FTS5 recall context rejecting expired facts."""
        now_iso = (now or datetime.now(tz=UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        acl_sql, acl_params = self._build_acl_where(access_ctx)

        with self._read_tx() as conn:
            pinned_rows = conn.execute(
                f"""
                SELECT * FROM memory_items
                WHERE kind IN ('preference', 'approved_procedure')
                  AND {acl_sql}
                  AND (valid_until IS NULL OR valid_until >= ?)
                ORDER BY
                  CASE kind WHEN 'approved_procedure' THEN 0 ELSE 1 END,
                  updated_at DESC,
                  seq DESC
                """,
                [*acl_params, now_iso],
            ).fetchall()

            pinned_blocks: list[str] = []
            pinned_ids: list[str] = []
            used_lines = 0
            used_bytes = 0

            for row in pinned_rows:
                block = self._format_memory_block(row)
                sep_lines = 1 if pinned_blocks else 0
                sep_bytes = 1 if pinned_blocks else 0
                block_lines = block.splitlines()
                add_lines = sep_lines + len(block_lines)
                add_bytes = sep_bytes + len(block.encode("utf-8"))
                if used_lines + add_lines <= PINNED_MAX_LINES and (
                    used_bytes + add_bytes <= PINNED_MAX_BYTES
                ):
                    pinned_blocks.append(block)
                    pinned_ids.append(str(row["id"]))
                    used_lines += add_lines
                    used_bytes += add_bytes
                elif not pinned_blocks:
                    # Truncate oversized single item safely inside 150 lines / 16 KB
                    kept_lines: list[str] = []
                    cur_bytes = 0
                    for line in block_lines[:PINNED_MAX_LINES]:
                        line_b = len((("\n" if kept_lines else "") + line).encode("utf-8"))
                        if cur_bytes + line_b > PINNED_MAX_BYTES:
                            break
                        kept_lines.append(line)
                        cur_bytes += line_b
                    if not kept_lines:
                        raw = block.encode("utf-8")[:PINNED_MAX_BYTES]
                        kept_lines = [raw.decode("utf-8", errors="ignore")]
                    pinned_blocks.append("\n".join(kept_lines))
                    pinned_ids.append(str(row["id"]))
                    break
                else:
                    break

            pinned_text = "\n".join(pinned_blocks)

            recalled_blocks: list[str] = []
            recalled_ids: list[str] = []
            fts_query = build_fts5_query(query, operator="OR") if query.strip() else None
            if fts_query is not None:
                m_acl_sql, m_acl_params = self._build_acl_where(access_ctx, table_alias="m")
                excl_sql = ""
                excl_params: list[Any] = []
                if pinned_ids:
                    placeholders = ", ".join("?" for _ in pinned_ids)
                    excl_sql = f" AND m.id NOT IN ({placeholders})"
                    excl_params = list(pinned_ids)

                recalled_rows = conn.execute(
                    f"""
                    SELECT m.* FROM memory_fts
                    JOIN memory_items m ON m.seq = memory_fts.rowid
                    WHERE memory_fts MATCH ?
                      AND {m_acl_sql}
                      AND (m.valid_until IS NULL OR m.valid_until >= ?)
                      {excl_sql}
                    ORDER BY bm25(memory_fts) ASC, m.updated_at DESC, m.seq DESC
                    LIMIT ?
                    """,
                    [fts_query, *m_acl_params, now_iso, *excl_params, RECALL_MAX_MEMORY_ITEMS],
                ).fetchall()
                for row in recalled_rows:
                    recalled_blocks.append(self._format_memory_block(row))
                    recalled_ids.append(str(row["id"]))

        passage_blocks: list[str] = []
        for raw_passage in list(thread_passages)[:RECALL_MAX_THREAD_PASSAGES]:
            cleaned_p = raw_passage.strip()
            if not cleaned_p:
                continue
            safe_p, _ = redact_memory_text(cleaned_p)
            passage_blocks.append(f"[THREAD_PASSAGE authority=advisory_only]\n{safe_p}")

        recall_candidates = [*recalled_blocks, *passage_blocks]
        kept_recall: list[str] = []
        recalled_kept_count = 0
        passage_kept_count = 0
        used_recall_chars = 0

        for idx, block in enumerate(recall_candidates):
            sep = "\n\n" if kept_recall else ""
            candidate_len = len(sep) + len(block)
            if used_recall_chars + candidate_len <= RECALL_MAX_CHARS:
                kept_recall.append(block)
                used_recall_chars += candidate_len
                if idx < len(recalled_blocks):
                    recalled_kept_count += 1
                else:
                    passage_kept_count += 1
            else:
                remaining = RECALL_MAX_CHARS - used_recall_chars - len(sep)
                if remaining > 32:
                    kept_recall.append(block[:remaining])
                    if idx < len(recalled_blocks):
                        recalled_kept_count += 1
                    else:
                        passage_kept_count += 1
                break

        recall_text = "\n\n".join(kept_recall)
        if len(recall_text) > RECALL_MAX_CHARS:
            recall_text = recall_text[:RECALL_MAX_CHARS]

        sections: list[str] = []
        if pinned_text:
            sections.append(pinned_text)
        if recall_text:
            sections.append(recall_text)
        combined_text = "\n\n".join(sections)

        all_ids = tuple([*pinned_ids, *recalled_ids[:recalled_kept_count]])
        return MemoryContextBundle(
            pinned_text=pinned_text,
            recall_text=recall_text,
            combined_text=combined_text,
            pinned_count=len(pinned_ids),
            recalled_count=recalled_kept_count,
            passage_count=passage_kept_count,
            total_chars=len(combined_text),
            item_ids=all_ids,
        )

    def export_memories(
        self,
        access_ctx: MemoryAccessContext,
        *,
        fmt: Literal["json", "md"] = "md",
        scope: str | None = None,
        scope_id: str | None = None,
        kind: str | None = None,
        include_expired: bool = False,
        now: datetime | None = None,
    ) -> str:
        items = self.list_memories(
            access_ctx,
            scope=scope,
            scope_id=scope_id,
            kind=kind,
            include_expired=include_expired,
            limit=500,
            now=now,
        )
        sanitized: list[dict[str, Any]] = []
        for item in items:
            clean_item = dict(item)
            clean_item["title"], _ = redact_memory_text(str(item["title"]))
            clean_item["content"], _ = redact_memory_text(str(item["content"]))
            clean_item["tags"], _ = redact_memory_text(str(item["tags"]))
            sanitized.append(clean_item)

        if self._audit_fn is not None:
            with self._write_tx() as conn:
                self._emit_audit(
                    conn,
                    actor=access_ctx.user_id or access_ctx.actor_role,
                    action="memory.export",
                    entity_id=None,
                    decision="allow",
                    detail={"format": fmt, "count": len(sanitized)},
                )

        if fmt == "json":
            return json.dumps({"items": sanitized}, indent=2, ensure_ascii=False)

        lines = ["# ControlBot Memory Export", ""]
        for item in sanitized:
            lines.append(f"## {item['title']} (`{item['id']}`)")
            lines.append(
                f"- **Scope**: `{item['scope']}:{item['scope_id']}` | "
                f"**Kind**: `{item['kind']}` | **Revision**: {item['revision']}"
            )
            lines.append(
                f"- **Observed**: `{item['observed_at'] or 'n/a'}` | "
                f"**Valid Until**: `{item['valid_until'] or 'none'}`"
            )
            lines.append("")
            lines.append(str(item["content"]))
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def export_to_file(
        self,
        path: Path | str,
        access_ctx: MemoryAccessContext,
        *,
        fmt: Literal["json", "md"] = "md",
        scope: str | None = None,
        scope_id: str | None = None,
        kind: str | None = None,
        include_expired: bool = False,
        now: datetime | None = None,
    ) -> Path:
        """Atomically export redacted memories to disk with strict 0600 permissions."""
        dest = Path(path)
        if dest.is_symlink():
            raise MemoryPermissionError(f"Refusing to overwrite symlink export target: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = self.export_memories(
            access_ctx,
            fmt=fmt,
            scope=scope,
            scope_id=scope_id,
            kind=kind,
            include_expired=include_expired,
            now=now,
        )
        tmp_path = dest.with_name(f".{dest.name}.{uuid.uuid4().hex[:8]}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), flags, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, dest)
        os.chmod(dest, 0o600)
        return dest
