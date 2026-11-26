"""Central Decide -> Record -> Act PolicyGateway with fail-closed safety_floor (CB-02)."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import inspect
import posixpath
import re
import shlex
import threading
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, TypeVar, overload

from pydantic import Field

from src.contracts.common import (
    FrozenModel,
    HttpOrigin,
    NonEmptyStr,
    UtcDatetime,
    ensure_utc,
    utc_now,
)
from src.contracts.envelope import Lane
from src.engine.loop_detector import canonical_json_hash
from src.engine.redaction import contains_unredacted_secret_strict, is_sensitive_key_strict

T = TypeVar("T")

AuditSink = Callable[[dict[str, Any]], int | str | None]
ReceiptSink = Callable[[str, str, str, dict[str, Any]], bool]

_RISK_RANK: dict[str, int] = {"read": 1, "write": 2, "admin": 3}

_CRITICAL_PATH_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/var",
    "/home",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
    "/opt",
    "/sys",
    "/proc",
    "/dev",
)

_DESTRUCTIVE_SAFETY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "destructive_rm_root_or_glob",
        re.compile(
            r"(?:^|\s|;|&&|\|\||\()(?:(?:/[^\s]+/)?rm)\s+"
            r"(?:(?:-[a-zA-Z]*[rf][a-zA-Z]*|--recursive|--force)\s+)+"
            r"(?:/\*?|~(?:/[^\s;|&\"')]*)?|\*|\.\.?/?|\$HOME(?:/[^\s;|&\"')]*)?|"
            r"\$\{HOME\}(?:/[^\s;|&\"')]*)?|"
            r"(?:/etc|/usr|/var|/home|/bin|/sbin|/lib|/lib64|/boot|/root|/opt|/sys|/proc|/dev)"
            r"(?:/[^\s;|&\"')]*)?)(?:\s|$|;|&|\||\"|'|\)|\})",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive_disk_format",
        re.compile(r"\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs|fdisk|parted)\b", re.IGNORECASE),
    ),
    (
        "destructive_dd_device",
        re.compile(r"\bdd\b[^;\n]*\bof=/dev/(?:sd|nvme|hd|vd|mmcblk|loop)\w*", re.IGNORECASE),
    ),
    (
        "destructive_sql_drop_truncate",
        re.compile(r"\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b", re.IGNORECASE),
    ),
    (
        "destructive_db_or_git_wipe",
        re.compile(
            r"(?:\brm\s+[^\n]*(?:\.git\b|\.sqlite3?\b|\.db\b)|git\s+(?:reset\s+--hard|push\s+(?:--force|-f)\b))",
            re.IGNORECASE,
        ),
    ),
    (
        "destructive_chmod_777_root",
        re.compile(
            r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+(?:777|a\+rwx)\s+"
            r"(?:/[^\s;|&\"']*|~[^\s;|&\"']*|\$HOME[^\s;|&\"']*)",
            re.IGNORECASE,
        ),
    ),
)

_SHELL_SUBSTITUTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell_command_substitution", re.compile(r"\$\(")),
    ("shell_process_substitution", re.compile(r"(?:^|[\s;|&=])[<>]\(")),
    ("shell_backtick_substitution", re.compile(r"`[^`]+`")),
    ("shell_pipe_to_interpreter", re.compile(r"\|\s*(?:ba|da|z|k)?sh\b", re.IGNORECASE)),
    ("shell_eval_exec", re.compile(r"(?:^|\s|;|&&|\()\s*(?:eval|exec)\s+", re.IGNORECASE)),
    (
        "shell_chained_rm",
        re.compile(r"(?:;|&&|\|\|)\s*(?:(?:/[^\s]+/)?rm)\b", re.IGNORECASE),
    ),
)


def _match_safety_patterns(text: str) -> str | None:
    low = text.lower()
    has_rm = "rm" in low
    for reason, pattern in _DESTRUCTIVE_SAFETY_PATTERNS:
        if (
            (reason == "destructive_rm_root_or_glob" and not has_rm)
            or (
                reason == "destructive_disk_format"
                and not ("mkfs" in low or "wipefs" in low or "fdisk" in low or "parted" in low)
            )
            or (reason == "destructive_dd_device" and not ("dd" in low and "of=/dev/" in low))
            or (
                reason == "destructive_sql_drop_truncate"
                and not ("drop" in low or "truncate" in low)
            )
            or (reason == "destructive_db_or_git_wipe" and not (has_rm or "git" in low))
            or (reason == "destructive_chmod_777_root" and "chmod" not in low)
        ):
            continue
        if pattern.search(text) is not None:
            return f"safety_floor:{reason}"
    for reason, pattern in _SHELL_SUBSTITUTION_PATTERNS:
        if (
            (reason == "shell_command_substitution" and "$(" not in text)
            or (reason == "shell_process_substitution" and "<(" not in text and ">(" not in text)
            or (reason == "shell_backtick_substitution" and "`" not in text)
            or (reason == "shell_pipe_to_interpreter" and not ("|" in text and "sh" in low))
            or (reason == "shell_eval_exec" and not ("eval" in low or "exec" in low))
            or (reason == "shell_chained_rm" and not has_rm)
        ):
            continue
        if pattern.search(text) is not None:
            return f"safety_floor:{reason}"
    return None

_RAW_SECRET_TOKEN_RE = re.compile(
    r"(?:"
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{8,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{12,}\b"
    r"|\bsk-(?:proj-|live-|test-|svcacct-)?[A-Za-z0-9_-]{16,}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}\b"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r")"
)

_SHELL_TOOL_HINTS: tuple[str, ...] = (
    "bash",
    "sh",
    "shell",
    "pty",
    "terminal",
    "exec",
    "command",
    "run_command",
)
_SHELL_ARG_KEYS: frozenset[str] = frozenset(
    {"command", "cmd", "shell", "script", "bash", "code", "command_line"}
)
_WRAPPER_COMMANDS: frozenset[str] = frozenset(
    {"sudo", "env", "command", "nohup", "nice", "time", "busybox", "timeout"}
)
_WRAPPER_ARG_OPTIONS: dict[str, frozenset[str]] = {
    "sudo": frozenset(
        {
            "-u",
            "-g",
            "-h",
            "-p",
            "-r",
            "-t",
            "-U",
            "-C",
            "-T",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--other-user",
            "--close-from",
            "--command-timeout",
        }
    ),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "timeout": frozenset({"-k", "-s", "--kill-after", "--signal"}),
}
_QUOTED_LITERAL_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'')
_SHUTIL_RMTREE_CALL_RE = re.compile(r"(?:shutil\s*\.\s*rmtree|\brmtree)\s*\(")


def _extract_top_level_rmtree_literals(text: str, start: int) -> list[str]:
    literals: list[str] = []
    args_spans: list[str] = []
    arg_start = start
    depth = 0
    in_single = False
    in_double = False
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args_spans.append(text[arg_start:i])
                break
            depth -= 1
        elif ch == "," and depth == 0:
            args_spans.append(text[arg_start:i])
            arg_start = i + 1
        i += 1
    for arg_idx, raw_arg in enumerate(args_spans):
        cand = raw_arg.strip()
        if not cand:
            continue
        if arg_idx == 0 and "=" not in cand:
            val_expr = cand
        elif cand.startswith("path") and "=" in cand:
            lhs, rhs = cand.split("=", 1)
            if lhs.strip() != "path":
                continue
            val_expr = rhs.strip()
        else:
            continue
        with contextlib.suppress(ValueError, SyntaxError):
            lit_val = ast.literal_eval(val_expr)
            if isinstance(lit_val, str):
                literals.append(lit_val)
    return literals


_ANSI_C_SIMPLE_ESCAPES: dict[str, str] = {
    "\\": "\\",
    "'": "'",
    '"': '"',
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "?": "?",
}


def _decode_ansi_c_escapes(content: str) -> str:
    if "\\" not in content:
        return content
    out: list[str] = []
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        esc = content[i + 1]
        if esc in _ANSI_C_SIMPLE_ESCAPES:
            out.append(_ANSI_C_SIMPLE_ESCAPES[esc])
            i += 2
            continue
        if esc in {"x", "u", "U"}:
            max_digits = 2 if esc == "x" else (4 if esc == "u" else 8)
            j = i + 2
            while j < n and j - (i + 2) < max_digits and content[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 2:
                code = int(content[i + 2 : j], 16)
                if 0 <= code <= 0x10FFFF and not (0xD800 <= code <= 0xDFFF):
                    out.append(chr(code))
                    i = j
                    continue
        elif esc in "01234567":
            j = i + 1
            while j < n and j - (i + 1) < 3 and content[j] in "01234567":
                j += 1
            out.append(chr(int(content[i + 1 : j], 8) & 0xFF))
            i = j
            continue
        elif esc == "c" and i + 2 < n:
            ctrl_ch = content[i + 2]
            out.append(
                chr(ord(ctrl_ch.upper()) ^ 64)
                if "@" <= ctrl_ch.upper() <= "_"
                else chr(ord(ctrl_ch) & 0x1F)
            )
            i += 3
            continue
        out.append(ch)
        out.append(esc)
        i += 2
    return "".join(out)


def _has_closing_ansi_single_quote(text: str, start: int) -> bool:
    idx = start
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch == "\\":
            idx += 2
            continue
        if ch == "'":
            return True
        idx += 1
    return False


def _unescape_posix_dquote_for_shlex(text: str) -> str:
    if '"' not in text or "\\" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt in {"$", "`"}:
                    out.append(nxt)
                    i += 2
                    continue
                out.append(ch)
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            while i < n and text[i] not in {"\n", "\r"}:
                out.append(text[i])
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_SHLEX_WS_SKIP_RE = re.compile(r"[ \t\r\n]+")
_SHLEX_UNQUOTED_SCAN_RE = re.compile(r"""[ \t\r\n'"\\]""")
_SHLEX_DQUOTE_SCAN_RE = re.compile(r'[\\"]')


def _fast_posix_shlex_split(text: str) -> list[str]:
    n = len(text)
    if n == 0:
        return []
    if "'" not in text and '"' not in text and "\\" not in text:
        return [part for part in _SHLEX_WS_SKIP_RE.split(text) if part]
    tokens: list[str] = []
    i = 0
    while i < n:
        if text[i] in " \t\r\n":
            m_ws = _SHLEX_WS_SKIP_RE.match(text, i)
            if m_ws is not None:
                i = m_ws.end()
            if i >= n:
                break
        buf: list[str] = []
        has_token = False
        while i < n:
            m = _SHLEX_UNQUOTED_SCAN_RE.search(text, i)
            if m is None:
                buf.append(text[i:])
                has_token = True
                i = n
                break
            pos = m.start()
            if pos > i:
                buf.append(text[i:pos])
                has_token = True
            ch = text[pos]
            if ch in " \t\r\n":
                i = pos
                break
            if ch == "'":
                has_token = True
                close = text.find("'", pos + 1)
                if close == -1:
                    raise ValueError("No closing quotation")
                if close > pos + 1:
                    buf.append(text[pos + 1 : close])
                i = close + 1
                continue
            if ch == '"':
                has_token = True
                j = pos + 1
                while True:
                    dm = _SHLEX_DQUOTE_SCAN_RE.search(text, j)
                    if dm is None:
                        raise ValueError("No closing quotation")
                    dpos = dm.start()
                    if dpos > j:
                        buf.append(text[j:dpos])
                    if text[dpos] == '"':
                        i = dpos + 1
                        break
                    if dpos + 1 >= n:
                        raise ValueError("No escaped character")
                    nxt = text[dpos + 1]
                    if nxt in ('"', "\\"):
                        buf.append(nxt)
                    else:
                        buf.append("\\")
                        buf.append(nxt)
                    j = dpos + 2
                continue
            has_token = True
            if pos + 1 >= n:
                raise ValueError("No escaped character")
            buf.append(text[pos + 1])
            i = pos + 2
        if has_token:
            tokens.append("".join(buf) if len(buf) > 1 else (buf[0] if buf else ""))
    return tokens


def _posix_shlex_split(text: str) -> list[str]:
    return _fast_posix_shlex_split(_unescape_posix_dquote_for_shlex(text))


def _normalize_ansi_c_quotes(text: str) -> str:
    if "$'" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            while i < n and text[i] not in {"\n", "\r"}:
                out.append(text[i])
                i += 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "'":
            j = i + 2
            close_idx = -1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "'":
                    close_idx = j
                    break
                j += 1
            if close_idx != -1:
                decoded = _decode_ansi_c_escapes(text[i + 2 : close_idx])
                out.append(shlex.quote(decoded))
                i = close_idx + 1
                continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _normalize_locale_dquotes(text: str) -> str:
    if '$"' not in text:
        return text
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            while i < n and text[i] not in {"\n", "\r"}:
                out.append(text[i])
                i += 1
            continue
        if (
            ch == "$"
            and i + 1 < n
            and text[i + 1] == '"'
            and _has_closing_double_quote(text, i + 2)
        ):
            in_double = True
            out.append('"')
            i += 2
            continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _deobfuscate_shell(text: str) -> str:
    cleaned = re.sub(r"\$\{?IFS\}?", " ", text)
    cleaned = cleaned.replace('""', "").replace("''", "")
    cleaned = re.sub(
        r"\\\\|\\([A-Za-z0-9_./-])",
        lambda m: "\\\\" if m.group(1) is None else m.group(1),
        cleaned,
    )
    return cleaned


def _extract_embedded_strings(
    text: str,
    *,
    max_depth: int = 6,
    pre_split_tokens: list[str] | None = None,
) -> list[str]:
    results: list[str] = []
    seen: set[str] = {text}
    queue: list[tuple[str, int]] = [(text, 0)]
    while queue and len(results) < 512:
        cur, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        candidates: list[str] = []
        base_cur = _strip_shell_line_continuations(cur) if "\\\n" in cur else cur
        if base_cur != cur:
            candidates.append(base_cur)
        norm_cur = _normalize_ansi_c_quotes(base_cur) if "$'" in base_cur else base_cur
        if '$"' in norm_cur:
            norm_cur = _normalize_locale_dquotes(norm_cur)
        if norm_cur != base_cur:
            candidates.append(norm_cur)
        for m in _QUOTED_LITERAL_RE.finditer(norm_cur):
            lit = m.group(1) if m.group(1) is not None else (m.group(2) or "")
            if lit:
                candidates.append(lit)
        if any(c in norm_cur for c in "'\"\\"):
            if depth == 0 and pre_split_tokens is not None:
                candidates.extend(pre_split_tokens)
            else:
                with contextlib.suppress(ValueError):
                    candidates.extend(_posix_shlex_split(norm_cur))
        for cand in candidates:
            s = cand.strip()
            if not s or s in seen:
                continue
            if s.isdigit() or s in {"|", ";", "&", "&&", "||"}:
                seen.add(s)
                continue
            seen.add(s)
            results.append(s)
            queue.append((s, depth + 1))
            if len(results) >= 512:
                break
    return results


def _is_critical_rm_target(target: str) -> bool:
    t = target.strip().strip("\"'")
    if not t:
        return False
    if t[0] not in "/.*~$" and "/" not in t:
        return False
    if t in {"/", "/*", "*", ".", "./", "..", "../"} or t.endswith("/.."):
        return True
    if t.startswith(("~", "$HOME", "${HOME}")):
        return True
    collapsed = re.sub(r"/+", "/", t) if "//" in t else t
    norm = posixpath.normpath(collapsed)
    if norm in {"/", "/*", "*", ".", ".."}:
        return True
    if norm.startswith(("~", "$HOME", "${HOME}")):
        return True
    return any(
        norm == prefix or norm.startswith(f"{prefix}/") for prefix in _CRITICAL_PATH_PREFIXES
    )


_SUBPROCESS_EXEC_FUNCS: frozenset[str] = frozenset(
    {"run", "Popen", "call", "check_call", "check_output"}
)
_OS_EXEC_FUNCS: frozenset[str] = frozenset({"system", "popen"})
_PYTHON_AST_TRIGGER_WORDS: tuple[str, ...] = ("rmtree", "subprocess", "system", "popen")
_PYTHON_MODULE_STMT_TYPES: tuple[type[ast.stmt], ...] = (
    ast.Import,
    ast.ImportFrom,
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.If,
    ast.With,
    ast.AsyncWith,
    ast.Try,
)
_NON_STR_VAL: object = object()
_MAX_TRACKED_LIST_LEN: int = 1024
_MAX_TRACKED_STR_LEN: int = 65536


def _dunder_import_module(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _extract_ast_int(node: ast.AST) -> int | None:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ):
        return node.value
    if isinstance(node, ast.NamedExpr):
        return _extract_ast_int(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _extract_ast_int(node.operand)
        return -inner if inner is not None else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
        return _extract_ast_int(node.operand)
    return None


def _is_ast_none(node: ast.AST | None) -> bool:
    return node is None or (isinstance(node, ast.Constant) and node.value is None)


def _extract_ast_slice_obj(
    slice_node: ast.AST,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
) -> slice | None:
    if not isinstance(slice_node, ast.Slice):
        return None
    extract_int = int_resolver or _extract_ast_int
    start: int | None = None
    stop: int | None = None
    step: int | None = None
    valid = True
    if not _is_ast_none(slice_node.lower):
        assert slice_node.lower is not None
        start = extract_int(slice_node.lower)
        if expr_flusher is not None:
            expr_flusher(slice_node.lower)
        if start is None:
            valid = False
    elif slice_node.lower is not None and expr_flusher is not None:
        expr_flusher(slice_node.lower)
    if not _is_ast_none(slice_node.upper):
        assert slice_node.upper is not None
        stop = extract_int(slice_node.upper)
        if expr_flusher is not None:
            expr_flusher(slice_node.upper)
        if stop is None:
            valid = False
    elif slice_node.upper is not None and expr_flusher is not None:
        expr_flusher(slice_node.upper)
    if not _is_ast_none(slice_node.step):
        assert slice_node.step is not None
        step = extract_int(slice_node.step)
        if expr_flusher is not None:
            expr_flusher(slice_node.step)
        if step is None or step == 0:
            valid = False
    elif slice_node.step is not None and expr_flusher is not None:
        expr_flusher(slice_node.step)
    return slice(start, stop, step) if valid else None


def _apply_ast_slice(
    cur: Any,
    slice_node: ast.AST,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
) -> Any:
    if not isinstance(cur, (list, tuple, str)):
        if isinstance(slice_node, ast.Slice) and expr_flusher is not None:
            for bound in (slice_node.lower, slice_node.upper, slice_node.step):
                if bound is not None:
                    expr_flusher(bound)
        return None
    slice_obj = _extract_ast_slice_obj(
        slice_node, int_resolver=int_resolver, expr_flusher=expr_flusher
    )
    if slice_obj is None:
        return None
    sliced = cur[slice_obj]
    return list(sliced) if isinstance(cur, tuple) else sliced


def _slice_assign_new_len(cur_len: int, slice_obj: slice, rhs_len: int) -> int | None:
    if slice_obj.step is not None and slice_obj.step != 1:
        expected_len = len(range(*slice_obj.indices(cur_len)))
        return cur_len if rhs_len == expected_len else None
    replaced_len = len(range(*slice_obj.indices(cur_len)))
    return cur_len - replaced_len + rhs_len


def _assign_list_slice(lst: list[Any], slice_obj: slice, rhs_vals: list[Any]) -> bool:
    new_len = _slice_assign_new_len(len(lst), slice_obj, len(rhs_vals))
    if new_len is None or new_len > _MAX_TRACKED_LIST_LEN:
        return False
    lst[slice_obj] = list(rhs_vals)
    return True


def _slice_rhs_lists(path_val: Any, fn_val: Any) -> tuple[list[Any] | None, list[Any] | None]:
    rhs_p: list[Any] | None
    if isinstance(path_val, (list, str)):
        if len(path_val) > _MAX_TRACKED_LIST_LEN:
            return None, None
        rhs_p = list(path_val)
    elif isinstance(path_val, Mapping):
        if len(path_val) > _MAX_TRACKED_LIST_LEN:
            return None, None
        rhs_p = [str(k) for k in path_val]
    elif isinstance(fn_val, list):
        if len(fn_val) > _MAX_TRACKED_LIST_LEN:
            return None, None
        rhs_p = [None] * len(fn_val)
    elif isinstance(fn_val, Mapping):
        if len(fn_val) > _MAX_TRACKED_LIST_LEN:
            return None, None
        rhs_p = [str(k) for k in fn_val]
    else:
        rhs_p = None

    rhs_f: list[Any] | None
    if isinstance(fn_val, list):
        if len(fn_val) > _MAX_TRACKED_LIST_LEN:
            return None, None
        rhs_f = list(fn_val)
    elif rhs_p is not None:
        rhs_f = [None] * len(rhs_p)
    else:
        rhs_f = None
    return rhs_p, rhs_f


def _is_setdefault_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setdefault"
        and bool(node.args)
    )


def _is_pop_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "pop"
        and not node.keywords
        and len(node.args) <= 2
    )


def _is_popitem_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "popitem"
        and not node.args
        and not node.keywords
    )


def _is_dict_fromkeys_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fromkeys"
        and not node.keywords
        and 1 <= len(node.args) <= 2
    )


def _unwrap_subscripts(node: ast.Subscript) -> tuple[ast.AST, list[ast.AST]]:
    slices: list[ast.AST] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Subscript):
        slices.append(cur.slice)
        cur = cur.value
    slices.reverse()
    return cur, slices


def _unwrap_access_chain(
    node: ast.AST,
) -> tuple[ast.AST, list[tuple[str, ast.AST]]]:
    """Iteratively unwrap Subscript, Slice, .copy(), .keys(), .values(), and .get/.setdefault."""
    steps: list[tuple[str, ast.AST]] = []
    cur: ast.AST = node
    while True:
        if isinstance(cur, ast.Subscript):
            if isinstance(cur.slice, ast.Slice):
                steps.append(("slice", cur.slice))
            else:
                steps.append(("sub", cur.slice))
            cur = cur.value
        elif (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr == "copy"
            and not cur.args
            and not cur.keywords
        ):
            steps.append(("copy", cur))
            cur = cur.func.value
        elif (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr == "keys"
            and not cur.args
            and not cur.keywords
        ):
            steps.append(("keys", cur))
            cur = cur.func.value
        elif (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr == "values"
            and not cur.args
            and not cur.keywords
        ):
            steps.append(("values", cur))
            cur = cur.func.value
        elif (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr in {"get", "setdefault"}
            and cur.args
        ):
            steps.append((cur.func.attr, cur))
            cur = cur.func.value
        else:
            break
    steps.reverse()
    return cur, steps


def _flatten_binop_spine(node: ast.BinOp, op_type: type[ast.operator]) -> list[ast.AST]:
    operands: list[ast.AST] = []
    stack: list[ast.AST] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.BinOp) and isinstance(cur.op, op_type):
            stack.append(cur.right)
            stack.append(cur.left)
        else:
            operands.append(cur)
    return operands


def _is_dict_ctor_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dict"
    )


def _is_seq_ctor_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "tuple"}
        and not node.keywords
    )


def _is_reversed_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "reversed"
        and len(node.args) == 1
        and not node.keywords
    )


def _is_sorted_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "sorted"
        and len(node.args) == 1
    )


def _is_seq_producing_call(node: ast.AST) -> bool:
    return _is_seq_ctor_call(node) or _is_sorted_call(node)


def _is_default_os_path_join(func_node: ast.AST) -> bool:
    if isinstance(func_node, ast.Attribute) and func_node.attr == "join":
        recv = func_node.value
        if isinstance(recv, ast.Name) and recv.id == "posixpath":
            return True
        if _dunder_import_module(recv) in {"os.path", "posixpath"}:
            return True
        if isinstance(recv, ast.Attribute) and recv.attr == "path":
            if isinstance(recv.value, ast.Name) and recv.value.id == "os":
                return True
            if _dunder_import_module(recv.value) == "os":
                return True
    return False


class _AstPathCtx:
    __slots__ = (
        "iterable_path_resolver",
        "path_join_checker",
        "sorted_path_resolver",
        "truthiness_resolver",
    )

    def __init__(
        self,
        *,
        iterable_path_resolver: Callable[[ast.AST], list[Any] | None] | None = None,
        sorted_path_resolver: Callable[[ast.Call], list[Any] | None] | None = None,
        path_join_checker: Callable[[ast.AST], bool] | None = None,
        truthiness_resolver: Callable[[ast.AST], bool | None] | None = None,
    ) -> None:
        self.iterable_path_resolver = iterable_path_resolver
        self.sorted_path_resolver = sorted_path_resolver
        self.path_join_checker = path_join_checker
        self.truthiness_resolver = truthiness_resolver


def _extract_dict_call_path(
    call_node: ast.Call,
    path_vars: Mapping[str, str] | None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None,
    cmd_list_vars: Mapping[str, list[str]] | None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if call_node.args:
        arg0_val = _resolve_ast_container_or_value(
            call_node.args[0],
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(call_node.args[0])
        if isinstance(arg0_val, Mapping):
            out.update(arg0_val)
        elif isinstance(arg0_val, list):
            for pair in arg0_val:
                if isinstance(pair, (list, tuple)) and len(pair) == 2 and isinstance(pair[0], str):
                    val = pair[1]
                    if isinstance(val, dict):
                        out[pair[0]] = dict(val)
                    elif isinstance(val, list):
                        out[pair[0]] = list(val)
                    elif val is not None:
                        out[pair[0]] = val
                    else:
                        out[pair[0]] = _NON_STR_VAL
    for kw in call_node.keywords:
        if kw.arg is None:
            unpacked = _resolve_ast_container_or_value(
                kw.value,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(kw.value)
            if isinstance(unpacked, Mapping):
                out.update(unpacked)
        else:
            val = _resolve_ast_container_or_value(
                kw.value,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(kw.value)
            if isinstance(val, dict):
                out[kw.arg] = dict(val)
            elif isinstance(val, list):
                out[kw.arg] = list(val)
            elif val is not None:
                out[kw.arg] = val
            else:
                out[kw.arg] = _NON_STR_VAL
    return out


def _extract_seq_call_path(
    call_node: ast.Call,
    path_vars: Mapping[str, str] | None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None,
    cmd_list_vars: Mapping[str, list[str]] | None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> list[Any] | None:
    if _is_sorted_call(call_node):
        if ctx is not None and ctx.sorted_path_resolver is not None:
            return ctx.sorted_path_resolver(call_node)
        if expr_flusher is not None:
            for a in call_node.args:
                expr_flusher(a.value if isinstance(a, ast.Starred) else a)
            for kw in call_node.keywords:
                expr_flusher(kw.value)
        return None
    if not call_node.args:
        return []
    if len(call_node.args) != 1:
        if expr_flusher is not None:
            for a in call_node.args:
                expr_flusher(a.value if isinstance(a, ast.Starred) else a)
        return None
    arg0 = call_node.args[0]
    if isinstance(arg0, (ast.List, ast.Tuple)):
        if seq_path_resolver is not None:
            return seq_path_resolver(arg0)
        return _extract_ast_path_list(
            arg0,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if ctx is not None and ctx.iterable_path_resolver is not None and _is_reversed_call(arg0):
        return ctx.iterable_path_resolver(arg0)
    resolved = _resolve_ast_container_or_value(
        arg0,
        path_vars,
        dict_path_vars,
        cmd_list_vars,
        list_path_vars,
        list_fn_vars,
        fn_container_resolver=fn_container_resolver,
        pop_resolver=pop_resolver,
        seq_path_resolver=seq_path_resolver,
        dict_path_resolver=dict_path_resolver,
        int_resolver=int_resolver,
        dict_call_resolver=dict_call_resolver,
        setdefault_resolver=setdefault_resolver,
        expr_flusher=expr_flusher,
        ctx=ctx,
    )
    if expr_flusher is not None:
        expr_flusher(arg0)
    if isinstance(resolved, list):
        return list(resolved) if len(resolved) <= _MAX_TRACKED_LIST_LEN else None
    if isinstance(resolved, Mapping):
        return list(resolved.keys()) if len(resolved) <= _MAX_TRACKED_LIST_LEN else None
    if isinstance(resolved, str):
        return list(resolved) if len(resolved) <= _MAX_TRACKED_LIST_LEN else None
    return None


def _extract_ast_path_list(
    seq_node: ast.List | ast.Tuple,
    path_vars: Mapping[str, str] | None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None,
    cmd_list_vars: Mapping[str, list[str]] | None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> list[Any] | None:
    items: list[Any] = []
    has_unresolved_star = False
    for elt in seq_node.elts:
        if isinstance(elt, ast.Starred):
            if (
                ctx is not None
                and ctx.iterable_path_resolver is not None
                and _is_reversed_call(elt.value)
            ):
                unpacked: Any = ctx.iterable_path_resolver(elt.value)
            else:
                unpacked = _resolve_ast_container_or_value(
                    elt.value,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            if expr_flusher is not None:
                expr_flusher(elt.value)
            if isinstance(unpacked, list):
                if len(items) + len(unpacked) > _MAX_TRACKED_LIST_LEN:
                    return None
                items.extend(unpacked)
            elif isinstance(unpacked, Mapping):
                if len(items) + len(unpacked) > _MAX_TRACKED_LIST_LEN:
                    return None
                items.extend(str(k) for k in unpacked)
            elif isinstance(unpacked, str):
                if len(items) + len(unpacked) > _MAX_TRACKED_LIST_LEN:
                    return None
                items.extend(list(unpacked))
            elif fn_container_resolver is not None and isinstance(
                fn_unpacked := fn_container_resolver(elt.value), list
            ):
                if len(items) + len(fn_unpacked) > _MAX_TRACKED_LIST_LEN:
                    return None
                items.extend([None] * len(fn_unpacked))
            else:
                has_unresolved_star = True
                if len(items) + 1 > _MAX_TRACKED_LIST_LEN:
                    return None
                items.append(None)
        elif isinstance(elt, ast.Dict):
            sub_dict = (
                dict_path_resolver(elt)
                if dict_path_resolver is not None
                else _extract_ast_path_dict(
                    elt,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            )
            items.append(sub_dict)
        elif isinstance(elt, (ast.List, ast.Tuple)):
            sub_list = (
                seq_path_resolver(elt)
                if seq_path_resolver is not None
                else _extract_ast_path_list(
                    elt,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            )
            items.append(sub_list)
        elif isinstance(elt, ast.Name) and dict_path_vars and elt.id in dict_path_vars:
            items.append(dict(dict_path_vars[elt.id]))
        elif isinstance(elt, ast.Name) and list_path_vars and elt.id in list_path_vars:
            items.append(list(list_path_vars[elt.id]))
        elif isinstance(elt, ast.Name) and cmd_list_vars and elt.id in cmd_list_vars:
            items.append(list(cmd_list_vars[elt.id]))
        elif isinstance(elt, (ast.Subscript, ast.Call, ast.BinOp, ast.NamedExpr, ast.IfExp)):
            items.append(
                _resolve_ast_container_or_value(
                    elt,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            )
            if expr_flusher is not None:
                expr_flusher(elt)
        else:
            p_item: Any = _extract_ast_path_target(
                elt,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if p_item is None:
                p_item = int_resolver(elt) if int_resolver is not None else _extract_ast_int(elt)
            if expr_flusher is not None:
                expr_flusher(elt)
            items.append(p_item)
        if len(items) > _MAX_TRACKED_LIST_LEN:
            return None
    if not seq_node.elts:
        return []
    return items if (not has_unresolved_star or any(item is not None for item in items)) else None


def _extract_ast_path_dict(
    dict_node: ast.Dict,
    path_vars: Mapping[str, str] | None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None,
    cmd_list_vars: Mapping[str, list[str]] | None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for k_node, v_node in zip(dict_node.keys, dict_node.values, strict=False):
        if k_node is None:
            unpacked = _resolve_ast_container_or_value(
                v_node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(v_node)
            if isinstance(unpacked, Mapping):
                result.update(unpacked)
            continue
        k_str = _extract_ast_path_target(
            k_node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(k_node)
        if k_str is None:
            if expr_flusher is not None:
                expr_flusher(v_node)
            continue
        if isinstance(v_node, ast.Dict):
            sub_dict = (
                dict_path_resolver(v_node)
                if dict_path_resolver is not None
                else _extract_ast_path_dict(
                    v_node,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            )
            result[k_str] = sub_dict
        elif isinstance(v_node, (ast.List, ast.Tuple)):
            lst = (
                seq_path_resolver(v_node)
                if seq_path_resolver is not None
                else _extract_ast_path_list(
                    v_node,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
            )
            result[k_str] = lst if lst is not None else _NON_STR_VAL
        elif isinstance(v_node, ast.Name) and dict_path_vars and v_node.id in dict_path_vars:
            result[k_str] = dict(dict_path_vars[v_node.id])
        elif isinstance(v_node, ast.Name) and list_path_vars and v_node.id in list_path_vars:
            result[k_str] = list(list_path_vars[v_node.id])
        elif isinstance(v_node, ast.Name) and cmd_list_vars and v_node.id in cmd_list_vars:
            result[k_str] = list(cmd_list_vars[v_node.id])
        elif isinstance(v_node, (ast.Subscript, ast.Call, ast.BinOp, ast.NamedExpr, ast.IfExp)):
            sub_val = _resolve_ast_container_or_value(
                v_node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(v_node)
            result[k_str] = sub_val if sub_val is not None else _NON_STR_VAL
        else:
            p_val: Any = _extract_ast_path_target(
                v_node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if p_val is None:
                p_val = (
                    int_resolver(v_node) if int_resolver is not None else _extract_ast_int(v_node)
                )
            if expr_flusher is not None:
                expr_flusher(v_node)
            result[k_str] = p_val if p_val is not None else _NON_STR_VAL
    return result


def _resolve_ast_container_or_value(
    node: ast.AST,
    path_vars: Mapping[str, str] | None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None,
    cmd_list_vars: Mapping[str, list[str]] | None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> Any:
    if isinstance(node, ast.Name):
        if dict_path_vars is not None and node.id in dict_path_vars:
            return dict_path_vars[node.id]
        if list_path_vars is not None and node.id in list_path_vars:
            return list_path_vars[node.id]
        if cmd_list_vars is not None and node.id in cmd_list_vars:
            return cmd_list_vars[node.id]
        if path_vars is not None and node.id in path_vars:
            return path_vars[node.id]
        return int_resolver(node) if int_resolver is not None else None
    if isinstance(node, ast.Dict):
        if dict_path_resolver is not None:
            return dict_path_resolver(node)
        return _extract_ast_path_dict(
            node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, (ast.List, ast.Tuple)):
        if seq_path_resolver is not None:
            return seq_path_resolver(node)
        return _extract_ast_path_list(
            node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, ast.NamedExpr):
        if expr_flusher is not None:
            expr_flusher(node)
        return _resolve_ast_container_or_value(
            node.value,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, ast.IfExp):
        if expr_flusher is not None:
            expr_flusher(node.test)
        cond = (
            ctx.truthiness_resolver(node.test)
            if ctx is not None and ctx.truthiness_resolver is not None
            else None
        )
        if cond is True:
            b_val = _resolve_ast_container_or_value(
                node.body,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.body)
            return b_val
        if cond is False:
            o_val = _resolve_ast_container_or_value(
                node.orelse,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.orelse)
            return o_val
        b_val = _resolve_ast_container_or_value(
            node.body,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(node.body)
        o_val = _resolve_ast_container_or_value(
            node.orelse,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(node.orelse)
        if isinstance(b_val, str) and _is_critical_rm_target(b_val):
            return b_val
        if isinstance(o_val, str) and _is_critical_rm_target(o_val):
            return o_val
        if isinstance(b_val, str):
            return b_val
        if isinstance(o_val, str):
            return o_val
        return None
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.BitOr):
            operands = _flatten_binop_spine(node, ast.BitOr)
            merged: dict[str, Any] = {}
            for op_node in operands:
                resolved = _resolve_ast_container_or_value(
                    op_node,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
                if expr_flusher is not None:
                    expr_flusher(op_node)
                if not isinstance(resolved, Mapping):
                    return None
                merged.update(resolved)
            return merged
        if isinstance(node.op, ast.Add):
            operands = _flatten_binop_spine(node, ast.Add)
            resolved_ops: list[Any] = []
            for op_node in operands:
                resolved_ops.append(
                    _resolve_ast_container_or_value(
                        op_node,
                        path_vars,
                        dict_path_vars,
                        cmd_list_vars,
                        list_path_vars,
                        list_fn_vars,
                        fn_container_resolver=fn_container_resolver,
                        pop_resolver=pop_resolver,
                        seq_path_resolver=seq_path_resolver,
                        dict_path_resolver=dict_path_resolver,
                        int_resolver=int_resolver,
                        dict_call_resolver=dict_call_resolver,
                        setdefault_resolver=setdefault_resolver,
                        expr_flusher=expr_flusher,
                        ctx=ctx,
                    )
                )
                if expr_flusher is not None:
                    expr_flusher(op_node)
            if all(isinstance(r, str) for r in resolved_ops):
                total_len = 0
                for r in resolved_ops:
                    total_len += len(r)
                    if total_len > _MAX_TRACKED_STR_LEN:
                        return None
                return "".join(resolved_ops)
            if any(isinstance(r, list) for r in resolved_ops):
                combined: list[Any] = []
                for op_node, r in zip(operands, resolved_ops, strict=True):
                    if isinstance(r, list):
                        if len(combined) + len(r) > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend(r)
                    elif (
                        r is None
                        and isinstance(op_node, (ast.List, ast.Tuple))
                        and not any(isinstance(e, ast.Starred) for e in op_node.elts)
                    ):
                        if len(combined) + len(op_node.elts) > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * len(op_node.elts))
                    elif (
                        r is None
                        and isinstance(op_node, ast.Name)
                        and list_fn_vars is not None
                        and op_node.id in list_fn_vars
                    ):
                        pad_len = len(list_fn_vars[op_node.id])
                        if len(combined) + pad_len > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * pad_len)
                    elif (
                        r is None
                        and fn_container_resolver is not None
                        and isinstance(fn_op := fn_container_resolver(op_node), list)
                    ):
                        pad_len = len(fn_op)
                        if len(combined) + pad_len > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * pad_len)
                    else:
                        return None
                return combined
            return None
        if isinstance(node.op, ast.Mult):
            left_int = (
                int_resolver(node.left)
                if int_resolver is not None
                else _extract_ast_int(node.left)
            )
            if left_int is not None:
                if expr_flusher is not None:
                    expr_flusher(node.left)
                if not (0 <= left_int <= 64):
                    return None
                seq_val_right = _resolve_ast_container_or_value(
                    node.right,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
                if expr_flusher is not None:
                    expr_flusher(node.right)
                seq_list_r: list[Any] | None = None
                if isinstance(seq_val_right, list):
                    seq_list_r = seq_val_right
                elif (
                    seq_val_right is None
                    and fn_container_resolver is not None
                    and isinstance(fn_seq_r := fn_container_resolver(node.right), list)
                ):
                    seq_list_r = [None] * len(fn_seq_r)
                if seq_list_r is None or len(seq_list_r) * left_int > _MAX_TRACKED_LIST_LEN:
                    return None
                return seq_list_r * left_int
            seq_val_left = _resolve_ast_container_or_value(
                node.left,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.left)
            right_rep_count = (
                int_resolver(node.right)
                if int_resolver is not None
                else _extract_ast_int(node.right)
            )
            if expr_flusher is not None:
                expr_flusher(node.right)
            if right_rep_count is None or not (0 <= right_rep_count <= 64):
                return None
            seq_list_l: list[Any] | None = None
            if isinstance(seq_val_left, list):
                seq_list_l = seq_val_left
            elif (
                seq_val_left is None
                and fn_container_resolver is not None
                and isinstance(fn_seq_l := fn_container_resolver(node.left), list)
            ):
                seq_list_l = [None] * len(fn_seq_l)
            if seq_list_l is None or len(seq_list_l) * right_rep_count > _MAX_TRACKED_LIST_LEN:
                return None
            return seq_list_l * right_rep_count
        return _extract_ast_path_target(
            node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, ast.Call):
        if pop_resolver is not None and (_is_pop_call(node) or _is_popitem_call(node)):
            return pop_resolver(node)
        if _is_dict_ctor_call(node) or _is_dict_fromkeys_call(node):
            if dict_call_resolver is not None:
                return dict_call_resolver(node)
            if _is_dict_fromkeys_call(node):
                return None
            return _extract_dict_call_path(
                node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
        if _is_seq_producing_call(node):
            return _extract_seq_call_path(
                node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
    if isinstance(node, (ast.Subscript, ast.Call)):
        base, steps = _unwrap_access_chain(node)
        if steps:
            cur: Any = _resolve_ast_container_or_value(
                base,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            for kind, step_node in steps:
                if kind == "copy":
                    if isinstance(cur, dict):
                        cur = dict(cur)
                    elif isinstance(cur, list):
                        cur = list(cur)
                    else:
                        cur = None
                elif kind == "slice":
                    cur = _apply_ast_slice(
                        cur, step_node, int_resolver=int_resolver, expr_flusher=expr_flusher
                    )
                elif kind == "keys":
                    cur = [str(k) for k in cur] if isinstance(cur, Mapping) else None
                elif kind == "values":
                    cur = (
                        [None if v is _NON_STR_VAL else v for v in cur.values()]
                        if isinstance(cur, Mapping)
                        else None
                    )
                elif kind == "sub":
                    if isinstance(cur, Mapping):
                        k_str = _extract_ast_path_target(
                            step_node,
                            path_vars,
                            dict_path_vars,
                            cmd_list_vars,
                            list_path_vars,
                            list_fn_vars,
                            fn_container_resolver=fn_container_resolver,
                            pop_resolver=pop_resolver,
                            seq_path_resolver=seq_path_resolver,
                            dict_path_resolver=dict_path_resolver,
                            int_resolver=int_resolver,
                            dict_call_resolver=dict_call_resolver,
                            setdefault_resolver=setdefault_resolver,
                            expr_flusher=expr_flusher,
                            ctx=ctx,
                        )
                        if expr_flusher is not None:
                            expr_flusher(step_node)
                        cur = None if k_str is None or k_str not in cur else cur[k_str]
                    elif isinstance(cur, list):
                        idx = (
                            int_resolver(step_node)
                            if int_resolver is not None
                            else _extract_ast_int(step_node)
                        )
                        if expr_flusher is not None:
                            expr_flusher(step_node)
                        cur = None if idx is None or not (-len(cur) <= idx < len(cur)) else cur[idx]
                    else:
                        if expr_flusher is not None:
                            expr_flusher(step_node)
                        cur = None
                elif kind in {"get", "setdefault"}:
                    assert isinstance(step_node, ast.Call)
                    assert isinstance(step_node.func, ast.Attribute)
                    if kind == "setdefault" and setdefault_resolver is not None:
                        handled_sd, sd_val = setdefault_resolver(step_node)
                        if handled_sd:
                            cur = sd_val
                            continue
                    if isinstance(cur, Mapping):
                        k_str = _extract_ast_path_target(
                            step_node.args[0],
                            path_vars,
                            dict_path_vars,
                            cmd_list_vars,
                            list_path_vars,
                            list_fn_vars,
                            fn_container_resolver=fn_container_resolver,
                            pop_resolver=pop_resolver,
                            seq_path_resolver=seq_path_resolver,
                            dict_path_resolver=dict_path_resolver,
                            int_resolver=int_resolver,
                            dict_call_resolver=dict_call_resolver,
                            setdefault_resolver=setdefault_resolver,
                            expr_flusher=expr_flusher,
                            ctx=ctx,
                        )
                        if expr_flusher is not None:
                            expr_flusher(step_node.args[0])
                        default_node: ast.AST | None = (
                            step_node.args[1] if len(step_node.args) >= 2 else None
                        )
                        if default_node is None:
                            for kw in step_node.keywords:
                                if kw.arg == "default":
                                    default_node = kw.value
                                    break
                        if k_str is not None and k_str in cur:
                            if expr_flusher is not None and default_node is not None:
                                expr_flusher(default_node)
                            cur = cur[k_str]
                        else:
                            if default_node is not None:
                                cur = _resolve_ast_container_or_value(
                                    default_node,
                                    path_vars,
                                    dict_path_vars,
                                    cmd_list_vars,
                                    list_path_vars,
                                    list_fn_vars,
                                    fn_container_resolver=fn_container_resolver,
                                    pop_resolver=pop_resolver,
                                    seq_path_resolver=seq_path_resolver,
                                    dict_path_resolver=dict_path_resolver,
                                    int_resolver=int_resolver,
                                    dict_call_resolver=dict_call_resolver,
                                    setdefault_resolver=setdefault_resolver,
                                    expr_flusher=expr_flusher,
                                    ctx=ctx,
                                )
                                if expr_flusher is not None:
                                    expr_flusher(default_node)
                            else:
                                cur = None
                    elif step_node.func.attr == "get" and step_node.args:
                        env_key = _extract_ast_path_target(
                            step_node.args[0],
                            path_vars,
                            dict_path_vars,
                            cmd_list_vars,
                            list_path_vars,
                            list_fn_vars,
                            fn_container_resolver=fn_container_resolver,
                            pop_resolver=pop_resolver,
                            seq_path_resolver=seq_path_resolver,
                            dict_path_resolver=dict_path_resolver,
                            int_resolver=int_resolver,
                            dict_call_resolver=dict_call_resolver,
                            setdefault_resolver=setdefault_resolver,
                            expr_flusher=expr_flusher,
                            ctx=ctx,
                        )
                        if expr_flusher is not None:
                            for a in step_node.args:
                                expr_flusher(a.value if isinstance(a, ast.Starred) else a)
                            for kw in step_node.keywords:
                                expr_flusher(kw.value)
                        cur = "$HOME" if env_key == "HOME" else None
                    else:
                        if expr_flusher is not None:
                            for a in step_node.args:
                                expr_flusher(a.value if isinstance(a, ast.Starred) else a)
                            for kw in step_node.keywords:
                                expr_flusher(kw.value)
                        cur = None
            return None if cur is _NON_STR_VAL else cur
    p_target = _extract_ast_path_target(
        node,
        path_vars,
        dict_path_vars,
        cmd_list_vars,
        list_path_vars,
        list_fn_vars,
        fn_container_resolver=fn_container_resolver,
        pop_resolver=pop_resolver,
        seq_path_resolver=seq_path_resolver,
        dict_path_resolver=dict_path_resolver,
        int_resolver=int_resolver,
        dict_call_resolver=dict_call_resolver,
        setdefault_resolver=setdefault_resolver,
        expr_flusher=expr_flusher,
        ctx=ctx,
    )
    if p_target is not None:
        return p_target
    if isinstance(node, (ast.Subscript, ast.Call, ast.IfExp)):
        return _extract_ast_int(node)
    return int_resolver(node) if int_resolver is not None else _extract_ast_int(node)


def _extract_ast_path_target(
    node: ast.AST,
    path_vars: Mapping[str, str] | None = None,
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None = None,
    cmd_list_vars: Mapping[str, list[str]] | None = None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> str | None:
    def _flush_call_args_and_kws(c_node: ast.Call) -> None:
        if expr_flusher is None:
            return
        for a_node in c_node.args:
            expr_flusher(a_node.value if isinstance(a_node, ast.Starred) else a_node)
        for kw_node in c_node.keywords:
            expr_flusher(kw_node.value)

    def _resolve_join_args(c_node: ast.Call) -> list[str] | None:
        if c_node.keywords:
            _flush_call_args_and_kws(c_node)
            return None
        parts_out: list[str] = []
        total_len = 0
        failed = False
        for arg in c_node.args:
            if isinstance(arg, ast.Starred):
                if (
                    ctx is not None
                    and ctx.iterable_path_resolver is not None
                    and _is_reversed_call(arg.value)
                ):
                    unpacked: Any = ctx.iterable_path_resolver(arg.value)
                else:
                    unpacked = _resolve_ast_container_or_value(
                        arg.value,
                        path_vars,
                        dict_path_vars,
                        cmd_list_vars,
                        list_path_vars,
                        list_fn_vars,
                        fn_container_resolver=fn_container_resolver,
                        pop_resolver=pop_resolver,
                        seq_path_resolver=seq_path_resolver,
                        dict_path_resolver=dict_path_resolver,
                        int_resolver=int_resolver,
                        dict_call_resolver=dict_call_resolver,
                        setdefault_resolver=setdefault_resolver,
                        expr_flusher=expr_flusher,
                        ctx=ctx,
                    )
                if expr_flusher is not None:
                    expr_flusher(arg.value)
                if not isinstance(unpacked, list) or not all(
                    isinstance(x, str) for x in unpacked
                ):
                    failed = True
                    continue
                for item in unpacked:
                    total_len += len(item) + 1
                    if total_len > _MAX_TRACKED_STR_LEN:
                        failed = True
                        break
                    parts_out.append(item)
                continue
            part_str = _extract_ast_path_target(
                arg,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(arg)
            if part_str is None:
                failed = True
                continue
            total_len += len(part_str) + 1
            if total_len > _MAX_TRACKED_STR_LEN:
                failed = True
                continue
            parts_out.append(part_str)
        return None if failed else parts_out

    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", errors="replace")
        return None
    if isinstance(node, ast.Name):
        return path_vars.get(node.id) if path_vars is not None else None
    if isinstance(node, ast.NamedExpr):
        if expr_flusher is not None:
            expr_flusher(node)
        return _extract_ast_path_target(
            node.value,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, ast.IfExp):
        if expr_flusher is not None:
            expr_flusher(node.test)
        cond = (
            ctx.truthiness_resolver(node.test)
            if ctx is not None and ctx.truthiness_resolver is not None
            else None
        )
        if cond is True:
            b_str = _extract_ast_path_target(
                node.body,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.body)
            return b_str
        if cond is False:
            o_str = _extract_ast_path_target(
                node.orelse,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.orelse)
            return o_str
        b_str = _extract_ast_path_target(
            node.body,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(node.body)
        o_str = _extract_ast_path_target(
            node.orelse,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(node.orelse)
        if b_str is not None and _is_critical_rm_target(b_str):
            return b_str
        if o_str is not None and _is_critical_rm_target(o_str):
            return o_str
        return b_str if b_str is not None else o_str
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        total_len = 0
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                total_len += len(part.value)
                if total_len > _MAX_TRACKED_STR_LEN:
                    return None
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                if part.format_spec is not None:
                    if expr_flusher is not None:
                        expr_flusher(part.value)
                        expr_flusher(part.format_spec)
                    return None
                val = _extract_ast_path_target(
                    part.value,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
                if expr_flusher is not None:
                    expr_flusher(part.value)
                if val is None:
                    return None
                total_len += len(val)
                if total_len > _MAX_TRACKED_STR_LEN:
                    return None
                parts.append(val)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            operands = _flatten_binop_spine(node, ast.Add)
            resolved_parts: list[str] = []
            total_len = 0
            for op_node in operands:
                part_str = _extract_ast_path_target(
                    op_node,
                    path_vars,
                    dict_path_vars,
                    cmd_list_vars,
                    list_path_vars,
                    list_fn_vars,
                    fn_container_resolver=fn_container_resolver,
                    pop_resolver=pop_resolver,
                    seq_path_resolver=seq_path_resolver,
                    dict_path_resolver=dict_path_resolver,
                    int_resolver=int_resolver,
                    dict_call_resolver=dict_call_resolver,
                    setdefault_resolver=setdefault_resolver,
                    expr_flusher=expr_flusher,
                    ctx=ctx,
                )
                if expr_flusher is not None:
                    expr_flusher(op_node)
                if part_str is None:
                    return None
                total_len += len(part_str)
                if total_len > _MAX_TRACKED_STR_LEN:
                    return None
                resolved_parts.append(part_str)
            return "".join(resolved_parts)
        if isinstance(node.op, ast.Div):
            left = _extract_ast_path_target(
                node.left,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.left)
            right = _extract_ast_path_target(
                node.right,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(node.right)
            if left is not None and right is not None:
                if len(left) + len(right) + 1 > _MAX_TRACKED_STR_LEN:
                    return None
                return posixpath.join(left, right)
        return None
    if isinstance(node, ast.Call):
        if pop_resolver is not None and (_is_pop_call(node) or _is_popitem_call(node)):
            resolved_pop = pop_resolver(node)
            return resolved_pop if isinstance(resolved_pop, str) else None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
            joinpath_chain: list[ast.Call] = []
            cur_jp: ast.AST = node
            while (
                isinstance(cur_jp, ast.Call)
                and isinstance(cur_jp.func, ast.Attribute)
                and cur_jp.func.attr == "joinpath"
            ):
                joinpath_chain.append(cur_jp)
                cur_jp = cur_jp.func.value
            base_path = _extract_ast_path_target(
                cur_jp,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(cur_jp)
            cur_joined = base_path
            for jp_call in reversed(joinpath_chain):
                jp_parts = _resolve_join_args(jp_call)
                if cur_joined is None or jp_parts is None:
                    cur_joined = None
                    continue
                total_len = len(cur_joined) + sum(len(p) + 1 for p in jp_parts)
                if total_len > _MAX_TRACKED_STR_LEN:
                    cur_joined = None
                    continue
                cur_joined = str(PurePosixPath(cur_joined, *jp_parts))
                if len(cur_joined) > _MAX_TRACKED_STR_LEN:
                    cur_joined = None
            return cur_joined
        is_os_join = (
            ctx is not None
            and ctx.path_join_checker is not None
            and ctx.path_join_checker(node.func)
        ) or _is_default_os_path_join(node.func)
        if is_os_join:
            join_parts = _resolve_join_args(node)
            if not join_parts:
                return None
            joined_os = posixpath.join(*join_parts)
            return joined_os if len(joined_os) <= _MAX_TRACKED_STR_LEN else None
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name in {"Path", "PurePosixPath", "PurePath", "PosixPath"} and node.args:
            path_parts = _resolve_join_args(node)
            if not path_parts:
                return None
            joined = str(PurePosixPath(*path_parts))
            return joined if len(joined) <= _MAX_TRACKED_STR_LEN else None
        if func_name in {"expanduser", "str"} and node.args:
            res_arg0 = _extract_ast_path_target(
                node.args[0],
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            _flush_call_args_and_kws(node)
            return res_arg0
        if (
            func_name in {"get", "setdefault"}
            and isinstance(node.func, ast.Attribute)
            and node.args
        ):
            resolved_get = _resolve_ast_container_or_value(
                node,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            return resolved_get if isinstance(resolved_get, str) else None
        if func_name in {"getenv", "get"} and node.args:
            env_key = _extract_ast_path_target(
                node.args[0],
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            _flush_call_args_and_kws(node)
            if env_key == "HOME":
                return "$HOME"
            return None
        if isinstance(node.func, ast.Attribute) and expr_flusher is not None:
            expr_flusher(node.func.value)
        _flush_call_args_and_kws(node)
        return None
    if isinstance(node, ast.Subscript):
        resolved = _resolve_ast_container_or_value(
            node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if isinstance(resolved, str):
            return resolved
        key_val = _extract_ast_path_target(
            node.slice,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if expr_flusher is not None:
            expr_flusher(node.slice)
        if key_val == "HOME":
            return "$HOME"
    return None


def _extract_ast_cmd_list(
    node: ast.AST,
    path_vars: Mapping[str, str],
    cmd_list_vars: Mapping[str, list[str]],
    dict_path_vars: Mapping[str, Mapping[str, Any]] | None = None,
    list_path_vars: Mapping[str, list[Any]] | None = None,
    list_fn_vars: Mapping[str, list[Any]] | None = None,
    fn_container_resolver: Callable[[ast.AST], Any] | None = None,
    pop_resolver: Callable[[ast.Call], Any] | None = None,
    seq_path_resolver: Callable[[ast.List | ast.Tuple], list[Any] | None] | None = None,
    dict_path_resolver: Callable[[ast.Dict], dict[str, Any]] | None = None,
    int_resolver: Callable[[ast.AST], int | None] | None = None,
    dict_call_resolver: Callable[[ast.Call], dict[str, Any]] | None = None,
    setdefault_resolver: Callable[[ast.Call], tuple[bool, Any]] | None = None,
    expr_flusher: Callable[[ast.AST], None] | None = None,
    ctx: _AstPathCtx | None = None,
) -> list[str] | None:
    if isinstance(node, ast.Name):
        found = cmd_list_vars.get(node.id)
        return list(found) if found is not None else None
    if isinstance(node, ast.NamedExpr):
        if expr_flusher is not None:
            expr_flusher(node)
        return _extract_ast_cmd_list(
            node.value,
            path_vars,
            cmd_list_vars,
            dict_path_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
    if isinstance(node, (ast.Subscript, ast.Call, ast.BinOp, ast.IfExp)):
        resolved = _resolve_ast_container_or_value(
            node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=fn_container_resolver,
            pop_resolver=pop_resolver,
            seq_path_resolver=seq_path_resolver,
            dict_path_resolver=dict_path_resolver,
            int_resolver=int_resolver,
            dict_call_resolver=dict_call_resolver,
            setdefault_resolver=setdefault_resolver,
            expr_flusher=expr_flusher,
            ctx=ctx,
        )
        if isinstance(resolved, list) and all(isinstance(x, str) for x in resolved):
            return list(resolved)
        return None
    if isinstance(node, (ast.List, ast.Tuple)):
        parts: list[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                if (
                    ctx is not None
                    and ctx.iterable_path_resolver is not None
                    and _is_reversed_call(elt.value)
                ):
                    unpacked: Any = ctx.iterable_path_resolver(elt.value)
                else:
                    unpacked = _resolve_ast_container_or_value(
                        elt.value,
                        path_vars,
                        dict_path_vars,
                        cmd_list_vars,
                        list_path_vars,
                        list_fn_vars,
                        fn_container_resolver=fn_container_resolver,
                        pop_resolver=pop_resolver,
                        seq_path_resolver=seq_path_resolver,
                        dict_path_resolver=dict_path_resolver,
                        int_resolver=int_resolver,
                        dict_call_resolver=dict_call_resolver,
                        setdefault_resolver=setdefault_resolver,
                        expr_flusher=expr_flusher,
                        ctx=ctx,
                    )
                if expr_flusher is not None:
                    expr_flusher(elt.value)
                if isinstance(unpacked, list) and all(isinstance(x, str) for x in unpacked):
                    if len(parts) + len(unpacked) > _MAX_TRACKED_LIST_LEN:
                        return None
                    parts.extend(unpacked)
                    continue
                if isinstance(unpacked, Mapping):
                    if len(parts) + len(unpacked) > _MAX_TRACKED_LIST_LEN:
                        return None
                    parts.extend(str(k) for k in unpacked)
                    continue
                return None
            part = _extract_ast_path_target(
                elt,
                path_vars,
                dict_path_vars,
                cmd_list_vars,
                list_path_vars,
                list_fn_vars,
                fn_container_resolver=fn_container_resolver,
                pop_resolver=pop_resolver,
                seq_path_resolver=seq_path_resolver,
                dict_path_resolver=dict_path_resolver,
                int_resolver=int_resolver,
                dict_call_resolver=dict_call_resolver,
                setdefault_resolver=setdefault_resolver,
                expr_flusher=expr_flusher,
                ctx=ctx,
            )
            if expr_flusher is not None:
                expr_flusher(elt)
            if part is None:
                return None
            if len(parts) >= _MAX_TRACKED_LIST_LEN:
                return None
            parts.append(part)
        return parts
    return None


_MUTATING_CONTAINER_METHODS: frozenset[str] = frozenset(
    {
        "pop",
        "popitem",
        "setdefault",
        "append",
        "insert",
        "extend",
        "clear",
        "update",
        "reverse",
        "sort",
    }
)


class _RhsSnapshot:
    __slots__ = (
        "callable_kind",
        "cmd_list",
        "dict_fn",
        "dict_path",
        "fn_val",
        "import_mod",
        "is_getattr",
        "list_fn",
        "list_path",
        "path_val",
    )

    def __init__(
        self,
        *,
        dict_fn: dict[str, Any] | None = None,
        dict_path: dict[str, Any] | None = None,
        list_fn: list[Any] | None = None,
        list_path: list[Any] | None = None,
        cmd_list: list[str] | None = None,
        path_val: Any = None,
        fn_val: Any = None,
        callable_kind: str | None = None,
        import_mod: str | None = None,
        is_getattr: bool = False,
    ) -> None:
        self.dict_fn = dict_fn
        self.dict_path = dict_path
        self.list_fn = list_fn
        self.list_path = list_path
        self.cmd_list = cmd_list
        self.path_val = path_val
        self.fn_val = fn_val
        self.callable_kind = callable_kind
        self.import_mod = import_mod
        self.is_getattr = is_getattr


def _check_python_ast_calls_impl(
    text: str,
    *,
    _ast_depth: int = 0,
    _ast_step_budget: list[int] | None = None,
    _step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
    _cmd_depth: int = 0,
    _seen_texts: set[str] | None = None,
    _truncated_out: list[bool] | None = None,
) -> tuple[str | None, bool]:
    if _ast_step_budget is None:
        _ast_step_budget = [0]
    if _step_budget is None:
        _step_budget = [0]
    if _char_budget is None:
        _char_budget = [0]
    low = text.lower()
    if not any(trigger in low for trigger in _PYTHON_AST_TRIGGER_WORDS):
        return None, False
    try:
        tree = ast.parse(text)
    except (RecursionError, MemoryError):
        return "safety_floor:python_ast_complexity_budget_exceeded", False
    except SyntaxError:
        if "rmtree" in low:
            for match in _SHUTIL_RMTREE_CALL_RE.finditer(text):
                call_head = match.group(0).split("(", 1)[0].lower()
                if "shutil" not in call_head and "shutil" not in low:
                    continue
                for lit in _extract_top_level_rmtree_literals(text, match.end()):
                    if _is_critical_rm_target(lit):
                        return "safety_floor:destructive_rm_root_or_glob", False
        return None, False

    is_python_module = isinstance(tree, ast.Module) and any(
        isinstance(stmt, _PYTHON_MODULE_STMT_TYPES) for stmt in tree.body
    )

    shutil_aliases: set[str] = {"shutil"}
    rmtree_aliases: set[str] = set()
    subprocess_aliases: set[str] = {"subprocess"}
    subprocess_fn_aliases: set[str] = set()
    os_aliases: set[str] = {"os"}
    os_fn_aliases: set[str] = set()
    os_path_aliases: set[str] = {"posixpath"}
    path_join_aliases: set[str] = set()
    builtins_aliases: set[str] = {"builtins"}
    getattr_aliases: set[str] = {"getattr"}
    path_vars: dict[str, str] = {}
    int_vars: dict[str, int] = {}
    cmd_list_vars: dict[str, list[str]] = {}
    list_path_vars: dict[str, list[Any]] = {}
    dict_fn_vars: dict[str, dict[str, Any]] = {}
    list_fn_vars: dict[str, list[Any]] = {}
    dict_path_vars: dict[str, dict[str, Any]] = {}
    applied_setdefault_results: dict[int, tuple[Any, Any]] = {}
    applied_setdefault_untracked: set[int] = set()
    popped_path_calls: dict[int, Any] = {}
    popped_fn_calls: dict[int, Any] = {}
    popped_dict_key_existed: dict[int, bool] = {}
    popitem_path_calls: dict[int, list[Any] | None] = {}
    popitem_fn_calls: dict[int, list[Any] | None] = {}
    seq_path_cache: dict[int, list[Any] | None] = {}
    seq_fn_cache: dict[tuple[int, bool], list[Any] | None] = {}
    dict_path_cache: dict[int, dict[str, Any]] = {}
    dict_fn_cache: dict[int, dict[str, Any]] = {}
    dict_call_path_cache: dict[int, dict[str, Any]] = {}
    dict_call_fn_cache: dict[int, dict[str, Any]] = {}
    applied_mutating_calls: set[int] = set()
    applied_named_exprs: set[int] = set()
    flushed_expr_nodes: set[int] = set()
    has_mutating_hint = any(method in low for method in _MUTATING_CONTAINER_METHODS)
    has_walrus_hint = ":=" in text
    truncated_by_depth = False

    def _resolve_path_pop(call_node: ast.Call) -> Any:
        if _is_popitem_call(call_node):
            return _apply_popitem_call(call_node, mode="path")
        return _apply_pop_call(call_node, mode="path")

    def _resolve_seq_path_cached(seq_node: ast.List | ast.Tuple) -> list[Any] | None:
        _, path_list = _build_seq_both(seq_node)
        return path_list

    def _resolve_dict_path_cached(dict_node: ast.Dict) -> dict[str, Any]:
        _, path_map = _build_dict_both(dict_node)
        return path_map

    def _resolve_dict_call_path_cached(call_node: ast.Call) -> dict[str, Any]:
        _, path_map = _build_dict_call_both(call_node)
        return path_map

    def _resolve_setdefault_path(call_node: ast.Call) -> tuple[bool, Any]:
        assert isinstance(call_node.func, ast.Attribute)
        handled, res_p, _ = _apply_dict_setdefault_checked(call_node.func.value, call_node)
        return handled, res_p

    def _resolve_setdefault_fn(call_node: ast.Call) -> tuple[bool, Any]:
        assert isinstance(call_node.func, ast.Attribute)
        handled, _, res_f = _apply_dict_setdefault_checked(call_node.func.value, call_node)
        return handled, res_f

    def _extract_int_node(ast_node: ast.AST) -> int | None:
        if isinstance(ast_node, ast.Name):
            return int_vars.get(ast_node.id)
        if isinstance(ast_node, ast.NamedExpr):
            _apply_named_expr(ast_node)
            return _extract_int_node(ast_node.value)
        if isinstance(ast_node, ast.UnaryOp) and isinstance(ast_node.op, ast.USub):
            inner = _extract_int_node(ast_node.operand)
            return -inner if inner is not None else None
        if isinstance(ast_node, ast.UnaryOp) and isinstance(ast_node.op, ast.UAdd):
            return _extract_int_node(ast_node.operand)
        direct = _extract_ast_int(ast_node)
        if direct is not None:
            return direct
        if isinstance(ast_node, (ast.Subscript, ast.Call, ast.IfExp)):
            resolved = _resolve_path_node(ast_node)
            if isinstance(resolved, int) and not isinstance(resolved, bool):
                return resolved
        return None

    def _extract_bool_node(ast_node: ast.AST) -> bool | None:
        cur = ast_node
        while isinstance(cur, ast.NamedExpr):
            _apply_named_expr(cur)
            cur = cur.value
        if isinstance(cur, ast.Constant) and isinstance(cur.value, (bool, int)):
            return bool(cur.value)
        int_val = _extract_int_node(cur)
        if int_val is not None:
            return bool(int_val)
        return None

    def _eval_static_truthiness(test_node: ast.AST) -> bool | None:
        cur = test_node
        negate = False
        while True:
            if isinstance(cur, ast.NamedExpr):
                _apply_named_expr(cur)
                cur = cur.value
                continue
            if isinstance(cur, ast.UnaryOp) and isinstance(cur.op, ast.Not):
                negate = not negate
                cur = cur.operand
                continue
            break
        res: bool | None = None
        if isinstance(cur, ast.Constant):
            res = bool(cur.value)
        else:
            p_str = _extract_path_str(cur)
            if p_str is not None:
                res = bool(p_str)
            else:
                i_val = _extract_int_node(cur)
                if i_val is not None:
                    res = bool(i_val)
                else:
                    c_val = _resolve_path_node(cur)
                    if isinstance(c_val, (list, dict)):
                        res = bool(c_val)
        if res is None:
            return None
        return (not res) if negate else res

    def _is_os_path_module(mod_node: ast.AST) -> bool:
        if isinstance(mod_node, ast.Name) and mod_node.id in os_path_aliases:
            return True
        if isinstance(mod_node, ast.Attribute) and mod_node.attr == "path":
            return _resolve_module_name(mod_node.value) == "os"
        return _dunder_import_module(mod_node) in {"os.path", "posixpath"}

    def _is_path_join_callable(func_node: ast.AST) -> bool:
        if isinstance(func_node, ast.Name):
            return func_node.id in path_join_aliases
        if isinstance(func_node, ast.Attribute) and func_node.attr == "join":
            return _is_os_path_module(func_node.value)
        return False

    def _resolve_iterable_both(
        iter_node: ast.AST, *, _allow_path_pad: bool = True
    ) -> tuple[list[Any] | None, list[Any] | None]:
        cur_it = iter_node
        rev_count = 0
        while _is_reversed_call(cur_it):
            assert isinstance(cur_it, ast.Call)
            rev_count += 1
            cur_it = cur_it.args[0]
        if isinstance(cur_it, (ast.List, ast.Tuple)):
            res_f, res_p = _build_seq_both(cur_it, _allow_path_pad=_allow_path_pad)
        elif _is_sorted_call(cur_it):
            assert isinstance(cur_it, ast.Call)
            res_f, res_p = _build_sorted_both(cur_it, _allow_path_pad=_allow_path_pad)
        elif _is_seq_ctor_call(cur_it):
            assert isinstance(cur_it, ast.Call)
            if not cur_it.args:
                res_f, res_p = [], []
            elif len(cur_it.args) == 1:
                res_f, res_p = _resolve_iterable_both(
                    cur_it.args[0], _allow_path_pad=_allow_path_pad
                )
            else:
                for a in cur_it.args:
                    _flush_unapplied_expr_calls(a.value if isinstance(a, ast.Starred) else a)
                res_f, res_p = None, None
        else:
            p_raw = _resolve_path_node(cur_it)
            f_raw = _resolve_fn_container(cur_it, _allow_path_pad=_allow_path_pad)
            _flush_unapplied_expr_calls(cur_it)
            res_p = None
            if isinstance(p_raw, list):
                res_p = list(p_raw) if len(p_raw) <= _MAX_TRACKED_LIST_LEN else None
            elif isinstance(p_raw, Mapping):
                res_p = list(p_raw.keys()) if len(p_raw) <= _MAX_TRACKED_LIST_LEN else None
            elif isinstance(p_raw, str):
                res_p = list(p_raw) if len(p_raw) <= _MAX_TRACKED_LIST_LEN else None
            res_f = None
            if isinstance(f_raw, list) and len(f_raw) <= _MAX_TRACKED_LIST_LEN:
                res_f = list(f_raw)
            elif _allow_path_pad and res_p is not None and f_raw is None:
                res_f = [None] * len(res_p)
        if rev_count % 2 == 1:
            if res_f is not None:
                res_f = list(reversed(res_f))
            if res_p is not None:
                res_p = list(reversed(res_p))
        return res_f, res_p

    def _build_sorted_both(
        call_node: ast.Call, *, _allow_path_pad: bool = True
    ) -> tuple[list[Any] | None, list[Any] | None]:
        key_ok = True
        rev_val = False
        kw_ok = True
        for kw in call_node.keywords:
            _flush_unapplied_expr_calls(kw.value)
            if kw.arg == "key":
                if not _is_ast_none(kw.value):
                    key_ok = False
            elif kw.arg == "reverse":
                b_val = _extract_bool_node(kw.value)
                if b_val is not None:
                    rev_val = b_val
                else:
                    kw_ok = False
            else:
                kw_ok = False
        if len(call_node.args) != 1 or isinstance(call_node.args[0], ast.Starred):
            for a in call_node.args:
                _flush_unapplied_expr_calls(a.value if isinstance(a, ast.Starred) else a)
            return None, None
        sub_fn, sub_path = _resolve_iterable_both(
            call_node.args[0], _allow_path_pad=_allow_path_pad
        )
        _flush_unapplied_expr_calls(call_node.args[0])
        if not key_ok or not kw_ok or sub_path is None:
            return None, None
        if isinstance(sub_fn, list) and any(x is not None for x in sub_fn):
            return None, None
        if all(isinstance(x, str) for x in sub_path):
            sorted_p: list[Any] = sorted(sub_path, reverse=rev_val)
            return None, sorted_p
        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in sub_path):
            sorted_p = sorted(sub_path, reverse=rev_val)
            return None, sorted_p
        return None, None

    def _resolve_iterable_path_only(iter_node: ast.AST) -> list[Any] | None:
        _, p_list = _resolve_iterable_both(iter_node, _allow_path_pad=False)
        return p_list

    def _resolve_sorted_path_only(call_node: ast.Call) -> list[Any] | None:
        _, p_list = _build_sorted_both(call_node, _allow_path_pad=False)
        return p_list

    ast_ctx = _AstPathCtx(
        iterable_path_resolver=_resolve_iterable_path_only,
        sorted_path_resolver=_resolve_sorted_path_only,
        path_join_checker=_is_path_join_callable,
        truthiness_resolver=_eval_static_truthiness,
    )

    def _apply_named_expr(named_node: ast.NamedExpr) -> None:
        node_id = id(named_node)
        if node_id in applied_named_exprs:
            return
        applied_named_exprs.add(node_id)
        _record_binding(named_node.target, named_node.value)

    def _flush_unapplied_expr_calls(expr: ast.AST) -> None:
        if not has_mutating_hint and not has_walrus_hint:
            return
        expr_id = id(expr)
        if expr_id in flushed_expr_nodes:
            return
        flushed_expr_nodes.add(expr_id)
        expr_stack: list[ast.AST] = [expr]
        while expr_stack:
            cur = expr_stack.pop()
            if isinstance(
                cur,
                (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
            ):
                continue
            if isinstance(cur, ast.NamedExpr):
                _apply_named_expr(cur)
                continue
            if (
                isinstance(cur, ast.Call)
                and isinstance(cur.func, ast.Attribute)
                and cur.func.attr in _MUTATING_CONTAINER_METHODS
                and _resolve_callable_kind(cur.func) is None
            ):
                _apply_mutating_call(cur)
            if isinstance(cur, ast.Dict):
                dict_children: list[ast.AST] = []
                for dk, dv in zip(cur.keys, cur.values, strict=False):
                    if dk is not None:
                        dict_children.append(dk)
                    dict_children.append(dv)
                for child in reversed(dict_children):
                    expr_stack.append(child)
                continue
            children = list(ast.iter_child_nodes(cur))
            for child in reversed(children):
                expr_stack.append(child)

    def _flush_unapplied_pops(expr: ast.AST) -> None:
        _flush_unapplied_expr_calls(expr)

    def _resolve_path_node(ast_node: ast.AST) -> Any:
        return _resolve_ast_container_or_value(
            ast_node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=_resolve_fn_no_pad,
            pop_resolver=_resolve_path_pop,
            seq_path_resolver=_resolve_seq_path_cached,
            dict_path_resolver=_resolve_dict_path_cached,
            int_resolver=_extract_int_node,
            dict_call_resolver=_resolve_dict_call_path_cached,
            setdefault_resolver=_resolve_setdefault_path,
            expr_flusher=_flush_unapplied_expr_calls,
            ctx=ast_ctx,
        )

    def _extract_path_str(ast_node: ast.AST) -> str | None:
        return _extract_ast_path_target(
            ast_node,
            path_vars,
            dict_path_vars,
            cmd_list_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=_resolve_fn_no_pad,
            pop_resolver=_resolve_path_pop,
            seq_path_resolver=_resolve_seq_path_cached,
            dict_path_resolver=_resolve_dict_path_cached,
            int_resolver=_extract_int_node,
            dict_call_resolver=_resolve_dict_call_path_cached,
            setdefault_resolver=_resolve_setdefault_path,
            expr_flusher=_flush_unapplied_expr_calls,
            ctx=ast_ctx,
        )

    def _extract_cmd_lst(ast_node: ast.AST) -> list[str] | None:
        return _extract_ast_cmd_list(
            ast_node,
            path_vars,
            cmd_list_vars,
            dict_path_vars,
            list_path_vars,
            list_fn_vars,
            fn_container_resolver=_resolve_fn_no_pad,
            pop_resolver=_resolve_path_pop,
            seq_path_resolver=_resolve_seq_path_cached,
            dict_path_resolver=_resolve_dict_path_cached,
            int_resolver=_extract_int_node,
            dict_call_resolver=_resolve_dict_call_path_cached,
            setdefault_resolver=_resolve_setdefault_path,
            expr_flusher=_flush_unapplied_expr_calls,
            ctx=ast_ctx,
        )

    def _clear_var_bindings(name: str) -> None:
        dict_fn_vars.pop(name, None)
        dict_path_vars.pop(name, None)
        list_fn_vars.pop(name, None)
        list_path_vars.pop(name, None)
        cmd_list_vars.pop(name, None)
        path_vars.pop(name, None)
        int_vars.pop(name, None)
        rmtree_aliases.discard(name)
        subprocess_fn_aliases.discard(name)
        os_fn_aliases.discard(name)
        os_path_aliases.discard(name)
        path_join_aliases.discard(name)
        shutil_aliases.discard(name)
        subprocess_aliases.discard(name)
        os_aliases.discard(name)
        builtins_aliases.discard(name)
        getattr_aliases.discard(name)

    def _is_getattr_call(call_node: ast.Call) -> bool:
        if isinstance(call_node.func, ast.Name) and call_node.func.id in getattr_aliases:
            return True
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr == "getattr":
            val = call_node.func.value
            if isinstance(val, ast.Name) and val.id in builtins_aliases:
                return True
            if _dunder_import_module(val) == "builtins":
                return True
        return False

    def _resolve_module_name(mod_node: ast.AST) -> str | None:
        if isinstance(mod_node, ast.Name):
            name = mod_node.id
            if name in shutil_aliases:
                return "shutil"
            if name in subprocess_aliases:
                return "subprocess"
            if name in os_aliases:
                return "os"
            return None
        return _dunder_import_module(mod_node)

    def _match_module_attr(target_mod: str | None, attr: str) -> str | None:
        if attr == "rmtree" and target_mod == "shutil":
            return "rmtree"
        if attr in _SUBPROCESS_EXEC_FUNCS and target_mod == "subprocess":
            return "subprocess_cmd"
        if attr in _OS_EXEC_FUNCS and target_mod == "os":
            return "os_cmd"
        return None

    def _build_seq_both(
        seq_node: ast.List | ast.Tuple, *, _allow_path_pad: bool = True
    ) -> tuple[list[Any] | None, list[Any] | None]:
        node_id = id(seq_node)
        fn_key = (node_id, _allow_path_pad)
        if node_id in seq_path_cache and fn_key in seq_fn_cache:
            return seq_fn_cache[fn_key], seq_path_cache[node_id]

        fn_list: list[Any] = []
        path_list: list[Any] = []
        has_unresolved_star = False
        exceeded_cap = False
        for elt in seq_node.elts:
            if isinstance(elt, ast.Starred):
                unpacked_fn: Any
                unpacked_path: Any
                if _is_reversed_call(elt.value):
                    unpacked_fn, unpacked_path = _resolve_iterable_both(
                        elt.value, _allow_path_pad=_allow_path_pad
                    )
                else:
                    unpacked_fn = _resolve_fn_container(elt.value, _allow_path_pad=_allow_path_pad)
                    unpacked_path = _resolve_path_node(elt.value)
                    _flush_unapplied_pops(elt.value)
                if isinstance(unpacked_fn, list):
                    if len(fn_list) + len(unpacked_fn) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    fn_list.extend(unpacked_fn)
                elif _allow_path_pad and isinstance(unpacked_path, (list, Mapping, str)):
                    if len(fn_list) + len(unpacked_path) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    fn_list.extend([None] * len(unpacked_path))
                else:
                    if len(fn_list) + 1 > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    fn_list.append(None)

                if isinstance(unpacked_path, list):
                    if len(path_list) + len(unpacked_path) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    path_list.extend(unpacked_path)
                elif isinstance(unpacked_path, Mapping):
                    if len(path_list) + len(unpacked_path) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    path_list.extend(str(k) for k in unpacked_path)
                elif isinstance(unpacked_path, str):
                    if len(path_list) + len(unpacked_path) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    path_list.extend(list(unpacked_path))
                elif isinstance(unpacked_fn, list):
                    if len(path_list) + len(unpacked_fn) > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    path_list.extend([None] * len(unpacked_fn))
                else:
                    has_unresolved_star = True
                    if len(path_list) + 1 > _MAX_TRACKED_LIST_LEN:
                        exceeded_cap = True
                        break
                    path_list.append(None)
            elif isinstance(elt, ast.Dict):
                sub_fn, sub_path = _build_dict_both(elt)
                fn_list.append(sub_fn)
                path_list.append(sub_path)
            elif isinstance(elt, (ast.List, ast.Tuple)):
                sub_fn_l, sub_path_l = _build_seq_both(elt, _allow_path_pad=_allow_path_pad)
                fn_list.append(sub_fn_l)
                path_list.append(sub_path_l)
            elif isinstance(elt, ast.Name):
                if elt.id in dict_fn_vars:
                    fn_list.append(dict(dict_fn_vars[elt.id]))
                elif elt.id in list_fn_vars:
                    fn_list.append(list(list_fn_vars[elt.id]))
                else:
                    fn_list.append(_resolve_callable_kind(elt))

                if elt.id in dict_path_vars:
                    path_list.append(dict(dict_path_vars[elt.id]))
                elif elt.id in list_path_vars:
                    path_list.append(list(list_path_vars[elt.id]))
                elif elt.id in cmd_list_vars:
                    path_list.append(list(cmd_list_vars[elt.id]))
                elif elt.id in int_vars:
                    path_list.append(int_vars[elt.id])
                else:
                    path_list.append(_extract_path_str(elt))
            elif isinstance(elt, (ast.Subscript, ast.Call, ast.BinOp, ast.NamedExpr, ast.IfExp)):
                fn_val = _resolve_fn_container(elt, _allow_path_pad=_allow_path_pad)
                path_val = _resolve_path_node(elt)
                _flush_unapplied_pops(elt)
                fn_list.append(fn_val)
                path_list.append(path_val)
            else:
                fn_list.append(_resolve_callable_kind(elt))
                p_item: Any = _extract_path_str(elt)
                if p_item is None:
                    p_item = _extract_ast_int(elt)
                _flush_unapplied_pops(elt)
                path_list.append(p_item)

            if len(path_list) > _MAX_TRACKED_LIST_LEN or len(fn_list) > _MAX_TRACKED_LIST_LEN:
                exceeded_cap = True
                break

        res_fn: list[Any] | None
        res_path: list[Any] | None
        if exceeded_cap:
            res_fn = None
            res_path = None
        elif not seq_node.elts:
            res_fn = []
            res_path = []
        else:
            res_fn = fn_list if any(item is not None for item in fn_list) else None
            res_path = (
                path_list
                if (not has_unresolved_star or any(item is not None for item in path_list))
                else None
            )
        seq_fn_cache[fn_key] = res_fn
        if node_id not in seq_path_cache:
            seq_path_cache[node_id] = res_path
        return res_fn, seq_path_cache[node_id]

    def _merge_dict_mapping(
        path_dst: dict[str, Any] | None,
        fn_dst: dict[str, Any] | None,
        src_path: Any,
        src_fn: Any,
    ) -> None:
        if isinstance(src_path, Mapping):
            if path_dst is not None:
                path_dst.update(src_path)
            if fn_dst is not None:
                fn_src = src_fn if isinstance(src_fn, Mapping) else {}
                for k_m in src_path:
                    if k_m in fn_src:
                        v_fn = fn_src[k_m]
                        if isinstance(v_fn, dict):
                            fn_dst[k_m] = dict(v_fn)
                        elif isinstance(v_fn, list):
                            fn_dst[k_m] = list(v_fn)
                        else:
                            fn_dst[k_m] = v_fn
                    else:
                        fn_dst.pop(k_m, None)
        elif fn_dst is not None and isinstance(src_fn, Mapping):
            fn_dst.update(src_fn)

    def _build_dict_both(dict_node: ast.Dict) -> tuple[dict[str, Any], dict[str, Any]]:
        node_id = id(dict_node)
        if node_id in dict_fn_cache and node_id in dict_path_cache:
            return dict_fn_cache[node_id], dict_path_cache[node_id]

        fn_map: dict[str, Any] = {}
        path_map: dict[str, Any] = {}
        for k_node, v_node in zip(dict_node.keys, dict_node.values, strict=False):
            if k_node is None:
                unpacked_fn = _resolve_fn_container(v_node)
                unpacked_path = _resolve_path_node(v_node)
                _merge_dict_mapping(path_map, fn_map, unpacked_path, unpacked_fn)
                _flush_unapplied_pops(v_node)
                continue
            k_str = _extract_path_str(k_node)
            _flush_unapplied_pops(k_node)
            if k_str is None:
                _flush_unapplied_pops(v_node)
                continue
            if isinstance(v_node, ast.Dict):
                sub_fn, sub_path = _build_dict_both(v_node)
                fn_map[k_str] = sub_fn
                path_map[k_str] = sub_path
            elif isinstance(v_node, (ast.List, ast.Tuple)):
                sub_list_fn, sub_list_path = _build_seq_both(v_node)
                if sub_list_fn is not None:
                    fn_map[k_str] = sub_list_fn
                else:
                    fn_map.pop(k_str, None)
                path_map[k_str] = sub_list_path if sub_list_path is not None else _NON_STR_VAL
            elif isinstance(v_node, ast.Name):
                if v_node.id in dict_fn_vars:
                    fn_map[k_str] = dict(dict_fn_vars[v_node.id])
                elif v_node.id in list_fn_vars:
                    fn_map[k_str] = list(list_fn_vars[v_node.id])
                else:
                    v_kind = _resolve_callable_kind(v_node)
                    if v_kind is not None:
                        fn_map[k_str] = v_kind
                    else:
                        fn_map.pop(k_str, None)

                if v_node.id in dict_path_vars:
                    path_map[k_str] = dict(dict_path_vars[v_node.id])
                elif v_node.id in list_path_vars:
                    path_map[k_str] = list(list_path_vars[v_node.id])
                elif v_node.id in cmd_list_vars:
                    path_map[k_str] = list(cmd_list_vars[v_node.id])
                elif v_node.id in int_vars:
                    path_map[k_str] = int_vars[v_node.id]
                else:
                    p_val = _extract_path_str(v_node)
                    path_map[k_str] = p_val if p_val is not None else _NON_STR_VAL
            elif isinstance(v_node, (ast.Subscript, ast.Call, ast.BinOp, ast.NamedExpr, ast.IfExp)):
                sub_fn_val = _resolve_fn_container(v_node)
                if sub_fn_val is not None:
                    fn_map[k_str] = sub_fn_val
                else:
                    fn_map.pop(k_str, None)
                sub_p_val = _resolve_path_node(v_node)
                path_map[k_str] = sub_p_val if sub_p_val is not None else _NON_STR_VAL
                _flush_unapplied_pops(v_node)
            else:
                v_kind = _resolve_callable_kind(v_node)
                if v_kind is not None:
                    fn_map[k_str] = v_kind
                else:
                    fn_map.pop(k_str, None)
                p_val2: Any = _extract_path_str(v_node)
                if p_val2 is None:
                    p_val2 = _extract_ast_int(v_node)
                _flush_unapplied_pops(v_node)
                path_map[k_str] = p_val2 if p_val2 is not None else _NON_STR_VAL
        dict_fn_cache[node_id] = fn_map
        dict_path_cache[node_id] = path_map
        return fn_map, path_map

    def _build_fn_list(
        seq_node: ast.List | ast.Tuple, *, _allow_path_pad: bool = True
    ) -> list[Any] | None:
        fn_list, _ = _build_seq_both(seq_node, _allow_path_pad=_allow_path_pad)
        return fn_list

    def _build_fn_dict(dict_node: ast.Dict) -> dict[str, Any]:
        fn_map, _ = _build_dict_both(dict_node)
        return fn_map

    def _build_dict_call_both(call_node: ast.Call) -> tuple[dict[str, Any], dict[str, Any]]:
        node_id = id(call_node)
        if node_id in dict_call_fn_cache and node_id in dict_call_path_cache:
            return dict_call_fn_cache[node_id], dict_call_path_cache[node_id]

        fn_map: dict[str, Any] = {}
        path_map: dict[str, Any] = {}
        if _is_dict_fromkeys_call(call_node):
            assert isinstance(call_node.func, ast.Attribute)
            recv = call_node.func.value
            is_dict_recv = (isinstance(recv, ast.Name) and recv.id == "dict") or isinstance(
                recv, ast.Dict
            )
            if not is_dict_recv:
                recv_p = _resolve_path_node(recv)
                recv_f = _resolve_fn_container(recv)
                is_dict_recv = isinstance(recv_p, Mapping) or isinstance(recv_f, Mapping)
            if _is_reversed_call(call_node.args[0]):
                keys_val: Any = _resolve_iterable_path_only(call_node.args[0])
            else:
                keys_val = _resolve_path_node(call_node.args[0])
            _flush_unapplied_expr_calls(call_node.args[0])
            val_node = call_node.args[1] if len(call_node.args) >= 2 else None
            v_fn: Any = None
            v_path: Any = None
            if val_node is not None:
                v_fn = _resolve_fn_container(val_node)
                v_path = _resolve_path_node(val_node)
                _flush_unapplied_expr_calls(val_node)
            if is_dict_recv:
                keys_list: list[str] = []
                if isinstance(keys_val, list):
                    keys_list = [k for k in keys_val[:_MAX_TRACKED_LIST_LEN] if isinstance(k, str)]
                elif isinstance(keys_val, Mapping):
                    keys_list = [str(k) for k in list(keys_val.keys())[:_MAX_TRACKED_LIST_LEN]]
                elif isinstance(keys_val, str):
                    keys_list = list(keys_val[:_MAX_TRACKED_LIST_LEN])
                for k_str in keys_list:
                    if isinstance(v_path, dict):
                        path_map[k_str] = dict(v_path)
                    elif isinstance(v_path, list):
                        path_map[k_str] = list(v_path)
                    elif v_path is not None:
                        path_map[k_str] = v_path
                    else:
                        path_map[k_str] = _NON_STR_VAL
                    if isinstance(v_fn, dict):
                        fn_map[k_str] = dict(v_fn)
                    elif isinstance(v_fn, list):
                        fn_map[k_str] = list(v_fn)
                    elif v_fn is not None:
                        fn_map[k_str] = v_fn
            dict_call_fn_cache[node_id] = fn_map
            dict_call_path_cache[node_id] = path_map
            return fn_map, path_map

        if call_node.args:
            arg0 = call_node.args[0]
            if isinstance(arg0, ast.Dict):
                sub_fn, sub_path = _build_dict_both(arg0)
                _merge_dict_mapping(path_map, fn_map, sub_path, sub_fn)
            else:
                arg0_fn: Any
                arg0_path: Any
                if isinstance(arg0, (ast.List, ast.Tuple)):
                    arg0_fn, arg0_path = _build_seq_both(arg0)
                else:
                    arg0_fn = _resolve_fn_container(arg0)
                    arg0_path = _resolve_path_node(arg0)
                    _flush_unapplied_expr_calls(arg0)
                _merge_dict_mapping(path_map, fn_map, arg0_path, arg0_fn)
                if isinstance(arg0_path, list):
                    for idx_p, p_pair in enumerate(arg0_path):
                        if (
                            isinstance(p_pair, (list, tuple))
                            and len(p_pair) == 2
                            and isinstance(p_pair[0], str)
                        ):
                            k_str = p_pair[0]
                            p_val = p_pair[1]
                            f_pair = (
                                arg0_fn[idx_p]
                                if isinstance(arg0_fn, list) and idx_p < len(arg0_fn)
                                else None
                            )
                            v_fn = (
                                f_pair[1]
                                if isinstance(f_pair, (list, tuple)) and len(f_pair) == 2
                                else None
                            )
                            if isinstance(p_val, dict):
                                path_map[k_str] = dict(p_val)
                            elif isinstance(p_val, list):
                                path_map[k_str] = list(p_val)
                            elif p_val is not None:
                                path_map[k_str] = p_val
                            else:
                                path_map[k_str] = _NON_STR_VAL
                            if isinstance(v_fn, dict):
                                fn_map[k_str] = dict(v_fn)
                            elif isinstance(v_fn, list):
                                fn_map[k_str] = list(v_fn)
                            elif v_fn is not None:
                                fn_map[k_str] = v_fn
                            else:
                                fn_map.pop(k_str, None)
        for kw in call_node.keywords:
            if kw.arg is None:
                unpacked_fn = _resolve_fn_container(kw.value)
                unpacked_path = _resolve_path_node(kw.value)
                _flush_unapplied_expr_calls(kw.value)
                _merge_dict_mapping(path_map, fn_map, unpacked_path, unpacked_fn)
            else:
                v_fn = _resolve_fn_container(kw.value)
                v_path = _resolve_path_node(kw.value)
                _flush_unapplied_expr_calls(kw.value)
                if isinstance(v_fn, dict):
                    fn_map[kw.arg] = dict(v_fn)
                elif isinstance(v_fn, list):
                    fn_map[kw.arg] = list(v_fn)
                elif v_fn is not None:
                    fn_map[kw.arg] = v_fn
                else:
                    fn_map.pop(kw.arg, None)

                if isinstance(v_path, dict):
                    path_map[kw.arg] = dict(v_path)
                elif isinstance(v_path, list):
                    path_map[kw.arg] = list(v_path)
                elif v_path is not None:
                    path_map[kw.arg] = v_path
                else:
                    path_map[kw.arg] = _NON_STR_VAL
        dict_call_fn_cache[node_id] = fn_map
        dict_call_path_cache[node_id] = path_map
        return fn_map, path_map

    def _extract_dict_call_fn(call_node: ast.Call) -> dict[str, Any]:
        fn_map, _ = _build_dict_call_both(call_node)
        return fn_map

    def _extract_seq_call_fn(
        call_node: ast.Call, *, _allow_path_pad: bool = True
    ) -> list[Any] | None:
        if _is_sorted_call(call_node):
            fn_sorted, _ = _build_sorted_both(call_node, _allow_path_pad=_allow_path_pad)
            return fn_sorted
        if not call_node.args:
            return []
        if len(call_node.args) != 1:
            return None
        arg0 = call_node.args[0]
        if isinstance(arg0, (ast.List, ast.Tuple)):
            return _build_fn_list(arg0, _allow_path_pad=_allow_path_pad)
        if _is_reversed_call(arg0) or _is_sorted_call(arg0) or _is_seq_ctor_call(arg0):
            fn_it, _ = _resolve_iterable_both(arg0, _allow_path_pad=_allow_path_pad)
            return fn_it
        resolved = _resolve_fn_container(arg0, _allow_path_pad=_allow_path_pad)
        if isinstance(resolved, list) and len(resolved) <= _MAX_TRACKED_LIST_LEN:
            return list(resolved)
        return None

    def _resolve_fn_container(
        node: ast.AST, *, _allow_path_pad: bool = True
    ) -> str | dict[str, Any] | list[Any] | None:
        if isinstance(node, ast.NamedExpr):
            _apply_named_expr(node)
            return _resolve_fn_container(node.value, _allow_path_pad=_allow_path_pad)
        if isinstance(node, ast.IfExp):
            _flush_unapplied_expr_calls(node.test)
            cond = _eval_static_truthiness(node.test)
            if cond is True:
                res_b = _resolve_fn_container(node.body, _allow_path_pad=_allow_path_pad)
                _flush_unapplied_expr_calls(node.body)
                return res_b
            if cond is False:
                res_o = _resolve_fn_container(node.orelse, _allow_path_pad=_allow_path_pad)
                _flush_unapplied_expr_calls(node.orelse)
                return res_o
            res_b = _resolve_fn_container(node.body, _allow_path_pad=_allow_path_pad)
            _flush_unapplied_expr_calls(node.body)
            res_o = _resolve_fn_container(node.orelse, _allow_path_pad=_allow_path_pad)
            _flush_unapplied_expr_calls(node.orelse)
            if isinstance(res_b, str) and res_b in {"rmtree", "subprocess_cmd", "os_cmd"}:
                return res_b
            if isinstance(res_o, str) and res_o in {"rmtree", "subprocess_cmd", "os_cmd"}:
                return res_o
            return None
        if isinstance(node, ast.Name):
            if node.id in dict_fn_vars:
                return dict_fn_vars[node.id]
            if node.id in list_fn_vars:
                return list_fn_vars[node.id]
        if isinstance(node, ast.Dict):
            return _build_fn_dict(node)
        if isinstance(node, (ast.List, ast.Tuple)):
            return _build_fn_list(node, _allow_path_pad=_allow_path_pad)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.BitOr):
                operands = _flatten_binop_spine(node, ast.BitOr)
                merged: dict[str, Any] = {}
                for op_node in operands:
                    resolved = _resolve_fn_container(op_node, _allow_path_pad=_allow_path_pad)
                    p_op = _resolve_path_node(op_node)
                    _flush_unapplied_expr_calls(op_node)
                    if isinstance(p_op, Mapping):
                        fn_src = resolved if isinstance(resolved, Mapping) else {}
                        for k_m in p_op:
                            if k_m in fn_src:
                                merged[k_m] = fn_src[k_m]
                            else:
                                merged.pop(k_m, None)
                    elif isinstance(resolved, Mapping):
                        merged.update(resolved)
                    else:
                        return None
                return merged
            if isinstance(node.op, ast.Add):
                operands = _flatten_binop_spine(node, ast.Add)
                resolved_ops: list[Any] = []
                for op_node in operands:
                    resolved_ops.append(
                        _resolve_fn_container(op_node, _allow_path_pad=_allow_path_pad)
                    )
                    _flush_unapplied_expr_calls(op_node)
                if not any(isinstance(r, list) for r in resolved_ops):
                    return None
                combined: list[Any] = []
                for op_node, resolved in zip(operands, resolved_ops, strict=True):
                    if isinstance(resolved, list):
                        if len(combined) + len(resolved) > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend(resolved)
                    elif (
                        resolved is None
                        and isinstance(op_node, (ast.List, ast.Tuple))
                        and not any(isinstance(e, ast.Starred) for e in op_node.elts)
                    ):
                        if len(combined) + len(op_node.elts) > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * len(op_node.elts))
                    elif (
                        resolved is None
                        and isinstance(op_node, ast.Name)
                        and op_node.id in list_path_vars
                    ):
                        pad_len = len(list_path_vars[op_node.id])
                        if len(combined) + pad_len > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * pad_len)
                    elif (
                        resolved is None
                        and _allow_path_pad
                        and isinstance(path_op := _resolve_path_node(op_node), list)
                    ):
                        pad_len = len(path_op)
                        if len(combined) + pad_len > _MAX_TRACKED_LIST_LEN:
                            return None
                        combined.extend([None] * pad_len)
                    else:
                        return None
                return combined
            if isinstance(node.op, ast.Mult):
                left_int = _extract_int_node(node.left)
                if left_int is not None:
                    _flush_unapplied_expr_calls(node.left)
                    if not (0 <= left_int <= 64):
                        return None
                    right_fn = _resolve_fn_container(
                        node.right, _allow_path_pad=_allow_path_pad
                    )
                    _flush_unapplied_expr_calls(node.right)
                    if (
                        isinstance(right_fn, list)
                        and len(right_fn) * left_int <= _MAX_TRACKED_LIST_LEN
                    ):
                        return right_fn * left_int
                    return None
                left_fn = _resolve_fn_container(
                    node.left, _allow_path_pad=_allow_path_pad
                )
                _flush_unapplied_expr_calls(node.left)
                right_int = _extract_int_node(node.right)
                _flush_unapplied_expr_calls(node.right)
                if (
                    right_int is not None
                    and 0 <= right_int <= 64
                    and isinstance(left_fn, list)
                    and len(left_fn) * right_int <= _MAX_TRACKED_LIST_LEN
                ):
                    return left_fn * right_int
                return None
            return None
        if isinstance(node, ast.Call):
            if _is_pop_call(node):
                pop_fn = _apply_pop_call(node, mode="fn")
                if isinstance(pop_fn, str):
                    return pop_fn
                if isinstance(pop_fn, dict):
                    return dict(pop_fn)
                if isinstance(pop_fn, list):
                    return list(pop_fn)
                return None
            if _is_popitem_call(node):
                return _apply_popitem_call(node, mode="fn")
            if _is_dict_ctor_call(node) or _is_dict_fromkeys_call(node):
                return _extract_dict_call_fn(node)
            if _is_seq_producing_call(node):
                return _extract_seq_call_fn(node, _allow_path_pad=_allow_path_pad)
            if _is_getattr_call(node) and len(node.args) >= 2:
                return _resolve_callable_kind(node)
        if isinstance(node, (ast.Subscript, ast.Call)):
            base, steps = _unwrap_access_chain(node)
            if not steps:
                return None
            cur: Any = _resolve_fn_container(base, _allow_path_pad=_allow_path_pad)
            for kind, step_node in steps:
                if kind == "copy":
                    if isinstance(cur, dict):
                        cur = dict(cur)
                    elif isinstance(cur, list):
                        cur = list(cur)
                    else:
                        cur = None
                elif kind == "slice":
                    cur = _apply_ast_slice(
                        cur,
                        step_node,
                        int_resolver=_extract_int_node,
                        expr_flusher=_flush_unapplied_expr_calls,
                    )
                elif kind == "keys":
                    cur = None
                elif kind == "values":
                    if isinstance(cur, Mapping):
                        path_map: Any = None
                        if (
                            _allow_path_pad
                            and isinstance(step_node, ast.Call)
                            and isinstance(step_node.func, ast.Attribute)
                        ):
                            path_map = _resolve_path_node(step_node.func.value)
                        vals = (
                            [cur.get(k) for k in path_map]
                            if isinstance(path_map, Mapping)
                            else list(cur.values())
                        )
                        cur = vals if any(v is not None for v in vals) else None
                    else:
                        cur = None
                elif kind == "sub":
                    if isinstance(cur, dict):
                        k_str = _extract_path_str(step_node)
                        _flush_unapplied_expr_calls(step_node)
                        cur = None if k_str is None or k_str not in cur else cur[k_str]
                    elif isinstance(cur, list):
                        idx = _extract_int_node(step_node)
                        _flush_unapplied_expr_calls(step_node)
                        cur = None if idx is None or not (-len(cur) <= idx < len(cur)) else cur[idx]
                    else:
                        _flush_unapplied_expr_calls(step_node)
                        cur = None
                elif kind in {"get", "setdefault"}:
                    assert isinstance(step_node, ast.Call)
                    if kind == "setdefault":
                        handled_sd, sd_fn = _resolve_setdefault_fn(step_node)
                        if handled_sd:
                            cur = sd_fn
                            continue
                    if isinstance(cur, dict):
                        k_str = _extract_path_str(step_node.args[0])
                        _flush_unapplied_expr_calls(step_node.args[0])
                        default_node: ast.AST | None = (
                            step_node.args[1] if len(step_node.args) >= 2 else None
                        )
                        if default_node is None:
                            for kw in step_node.keywords:
                                if kw.arg == "default":
                                    default_node = kw.value
                                    break
                        if k_str is not None and k_str in cur:
                            if default_node is not None:
                                _flush_unapplied_expr_calls(default_node)
                            cur = cur[k_str]
                        else:
                            if default_node is not None:
                                cur = _resolve_fn_container(
                                    default_node, _allow_path_pad=_allow_path_pad
                                )
                                _flush_unapplied_expr_calls(default_node)
                            else:
                                cur = None
                    else:
                        cur = None
            if isinstance(cur, str):
                return cur
            if isinstance(cur, dict):
                return dict(cur)
            if isinstance(cur, list):
                return list(cur)
            return None
        return _resolve_callable_kind(node)

    def _resolve_fn_no_pad(node: ast.AST) -> Any:
        return _resolve_fn_container(node, _allow_path_pad=False)

    def _resolve_callable_kind(func_node: ast.AST) -> str | None:
        if isinstance(func_node, ast.NamedExpr):
            _apply_named_expr(func_node)
            return _resolve_callable_kind(func_node.value)

        if isinstance(func_node, ast.IfExp):
            _flush_unapplied_expr_calls(func_node.test)
            cond = _eval_static_truthiness(func_node.test)
            if cond is True:
                k_b = _resolve_callable_kind(func_node.body)
                _flush_unapplied_expr_calls(func_node.body)
                return k_b
            if cond is False:
                k_o = _resolve_callable_kind(func_node.orelse)
                _flush_unapplied_expr_calls(func_node.orelse)
                return k_o
            k_b = _resolve_callable_kind(func_node.body)
            _flush_unapplied_expr_calls(func_node.body)
            k_o = _resolve_callable_kind(func_node.orelse)
            _flush_unapplied_expr_calls(func_node.orelse)
            if k_b in {"rmtree", "subprocess_cmd", "os_cmd"}:
                return k_b
            if k_o in {"rmtree", "subprocess_cmd", "os_cmd"}:
                return k_o
            return k_b or k_o

        if isinstance(func_node, ast.Attribute):
            if _is_path_join_callable(func_node):
                return "path_join"
            return _match_module_attr(_resolve_module_name(func_node.value), func_node.attr)

        if isinstance(func_node, ast.Name):
            ident = func_node.id
            if ident in rmtree_aliases or (ident == "rmtree" and "shutil" in low):
                return "rmtree"
            if ident in subprocess_fn_aliases:
                return "subprocess_cmd"
            if ident in os_fn_aliases:
                return "os_cmd"
            if ident in path_join_aliases:
                return "path_join"

        if isinstance(func_node, ast.Call):
            if _is_pop_call(func_node):
                resolved = _apply_pop_call(func_node, mode="fn")
                return resolved if isinstance(resolved, str) else None
            if _is_getattr_call(func_node) and len(func_node.args) >= 2:
                target_mod = _resolve_module_name(func_node.args[0])
                attr = _extract_path_str(func_node.args[1])
                if attr is not None:
                    if attr == "join" and _is_os_path_module(func_node.args[0]):
                        return "path_join"
                    return _match_module_attr(target_mod, attr)
                return None
            if (
                isinstance(func_node.func, ast.Attribute)
                and func_node.func.attr in {"get", "setdefault"}
                and func_node.args
            ):
                resolved = _resolve_fn_container(func_node)
                if isinstance(resolved, str):
                    return resolved
            return None

        if isinstance(func_node, ast.Subscript):
            resolved = _resolve_fn_container(func_node)
            if isinstance(resolved, str):
                return resolved
        return None

    def _snapshot_from_pair(f_item: Any, p_item: Any) -> _RhsSnapshot:
        if isinstance(f_item, dict) or isinstance(p_item, dict):
            d_f = dict(f_item) if isinstance(f_item, dict) else None
            d_p = dict(p_item) if isinstance(p_item, dict) else None
            return _RhsSnapshot(dict_fn=d_f, dict_path=d_p, path_val=d_p, fn_val=d_f)
        if isinstance(f_item, list) or isinstance(p_item, list):
            l_f = list(f_item) if isinstance(f_item, list) else None
            l_p = list(p_item) if isinstance(p_item, list) else None
            c_l = (
                list(p_item)
                if isinstance(p_item, list) and all(isinstance(x, str) for x in p_item)
                else None
            )
            return _RhsSnapshot(
                list_fn=l_f, list_path=l_p, cmd_list=c_l, path_val=l_p, fn_val=l_f
            )
        c_kind = f_item if isinstance(f_item, str) else None
        return _RhsSnapshot(path_val=p_item, fn_val=f_item, callable_kind=c_kind)

    def _eval_rhs_snapshot(value: ast.AST) -> _RhsSnapshot:
        if isinstance(value, ast.Name):
            src_name = value.id
            if (
                src_name in dict_fn_vars
                or src_name in dict_path_vars
                or src_name in list_fn_vars
                or src_name in list_path_vars
                or src_name in cmd_list_vars
            ):
                new_dict_fn = (
                    dict(dict_fn_vars[src_name]) if src_name in dict_fn_vars else None
                )
                new_dict_path = (
                    dict(dict_path_vars[src_name]) if src_name in dict_path_vars else None
                )
                new_list_fn = (
                    list(list_fn_vars[src_name]) if src_name in list_fn_vars else None
                )
                new_list_path = (
                    list(list_path_vars[src_name]) if src_name in list_path_vars else None
                )
                new_cmd_list = (
                    list(cmd_list_vars[src_name]) if src_name in cmd_list_vars else None
                )
                p_val: Any = (
                    new_dict_path
                    if new_dict_path is not None
                    else (new_list_path if new_list_path is not None else new_cmd_list)
                )
                f_val: Any = new_dict_fn if new_dict_fn is not None else new_list_fn
                return _RhsSnapshot(
                    dict_fn=new_dict_fn,
                    dict_path=new_dict_path,
                    list_fn=new_list_fn,
                    list_path=new_list_path,
                    cmd_list=new_cmd_list,
                    path_val=p_val,
                    fn_val=f_val,
                )

        if (
            isinstance(value, ast.Dict)
            or _is_dict_ctor_call(value)
            or _is_dict_fromkeys_call(value)
        ):
            if isinstance(value, ast.Dict):
                fn_map, path_map = _build_dict_both(value)
            else:
                assert isinstance(value, ast.Call)
                fn_map, path_map = _build_dict_call_both(value)
            fn_copy = dict(fn_map)
            path_copy = dict(path_map)
            return _RhsSnapshot(
                dict_fn=fn_copy, dict_path=path_copy, path_val=path_copy, fn_val=fn_copy
            )

        if isinstance(value, (ast.List, ast.Tuple)) or _is_seq_producing_call(value):
            if isinstance(value, (ast.List, ast.Tuple)):
                fn_list, path_list = _build_seq_both(value)
            else:
                assert isinstance(value, ast.Call)
                if (
                    _is_seq_ctor_call(value)
                    and len(value.args) == 1
                    and isinstance(value.args[0], (ast.List, ast.Tuple))
                ):
                    fn_list, path_list = _build_seq_both(value.args[0])
                else:
                    fn_list = _extract_seq_call_fn(value)
                    path_list = _extract_seq_call_path(
                        value,
                        path_vars,
                        dict_path_vars,
                        cmd_list_vars,
                        list_path_vars,
                        list_fn_vars,
                        fn_container_resolver=_resolve_fn_no_pad,
                        pop_resolver=_resolve_path_pop,
                        seq_path_resolver=_resolve_seq_path_cached,
                        dict_path_resolver=_resolve_dict_path_cached,
                        int_resolver=_extract_int_node,
                        dict_call_resolver=_resolve_dict_call_path_cached,
                        setdefault_resolver=_resolve_setdefault_path,
                        expr_flusher=_flush_unapplied_expr_calls,
                        ctx=ast_ctx,
                    )
            fn_l_copy = list(fn_list) if fn_list is not None else None
            path_l_copy = list(path_list) if path_list is not None else None
            cmd_l_copy = (
                list(path_l_copy)
                if path_l_copy is not None and all(isinstance(x, str) for x in path_l_copy)
                else None
            )
            return _RhsSnapshot(
                list_fn=fn_l_copy,
                list_path=path_l_copy,
                cmd_list=cmd_l_copy,
                path_val=path_l_copy,
                fn_val=fn_l_copy,
            )

        if isinstance(value, (ast.Subscript, ast.Call, ast.BinOp, ast.IfExp)):
            sub_fn = _resolve_fn_container(value)
            sub_path = _resolve_path_node(value)
            _flush_unapplied_expr_calls(value)
            if isinstance(sub_fn, dict) or isinstance(sub_path, dict):
                d_f = dict(sub_fn) if isinstance(sub_fn, dict) else None
                d_p = dict(sub_path) if isinstance(sub_path, dict) else None
                return _RhsSnapshot(dict_fn=d_f, dict_path=d_p, path_val=d_p, fn_val=d_f)
            if isinstance(sub_fn, list) or isinstance(sub_path, list):
                l_f = list(sub_fn) if isinstance(sub_fn, list) else None
                l_p = list(sub_path) if isinstance(sub_path, list) else None
                c_l = (
                    list(sub_path)
                    if isinstance(sub_path, list) and all(isinstance(x, str) for x in sub_path)
                    else None
                )
                return _RhsSnapshot(
                    list_fn=l_f, list_path=l_p, cmd_list=c_l, path_val=l_p, fn_val=l_f
                )
            c_kind = sub_fn if isinstance(sub_fn, str) else _resolve_callable_kind(value)
            mod = _dunder_import_module(value)
            if mod is None and _is_os_path_module(value):
                mod = "os.path"
            c_lst = _extract_cmd_lst(value) if sub_path is None else None
            return _RhsSnapshot(
                cmd_list=c_lst,
                path_val=sub_path,
                fn_val=sub_fn,
                callable_kind=c_kind,
                import_mod=mod,
            )

        is_getattr = (
            isinstance(value, ast.Attribute)
            and value.attr == "getattr"
            and (
                (isinstance(value.value, ast.Name) and value.value.id in builtins_aliases)
                or _dunder_import_module(value.value) == "builtins"
            )
        ) or (isinstance(value, ast.Name) and value.id in getattr_aliases)
        kind = _resolve_callable_kind(value)
        mod = _dunder_import_module(value)
        if mod is None and _is_os_path_module(value):
            mod = "os.path"
        p_val2 = _resolve_path_node(value)
        f_val2 = _resolve_fn_container(value)
        c_lst2 = _extract_cmd_lst(value) if not isinstance(p_val2, str) else None
        _flush_unapplied_expr_calls(value)
        return _RhsSnapshot(
            cmd_list=c_lst2,
            path_val=p_val2,
            fn_val=f_val2,
            callable_kind=kind,
            import_mod=mod,
            is_getattr=is_getattr,
        )

    def _split_snapshot_for_target(target: ast.AST, snap: _RhsSnapshot) -> Any:
        if not isinstance(target, (ast.Tuple, ast.List)):
            return snap
        seq_p = snap.list_path
        seq_f = snap.list_fn
        seq_len = (
            len(seq_p)
            if isinstance(seq_p, list)
            else (len(seq_f) if isinstance(seq_f, list) else None)
        )
        if seq_len is None:
            return None
        elem_snaps = [
            _snapshot_from_pair(
                seq_f[i] if isinstance(seq_f, list) and i < len(seq_f) else None,
                seq_p[i] if isinstance(seq_p, list) and i < len(seq_p) else None,
            )
            for i in range(seq_len)
        ]
        t_elts = target.elts
        star_indices = [i for i, e in enumerate(t_elts) if isinstance(e, ast.Starred)]
        if not star_indices:
            if len(t_elts) != len(elem_snaps):
                return None
            return [
                _split_snapshot_for_target(sub_t, sub_snap)
                for sub_t, sub_snap in zip(t_elts, elem_snaps, strict=True)
            ]
        if len(star_indices) == 1:
            star_idx = star_indices[0]
            before = star_idx
            after = len(t_elts) - star_idx - 1
            if len(elem_snaps) < before + after:
                return None
            mid_end = len(elem_snaps) - after
            out: list[Any] = [
                _split_snapshot_for_target(t_elts[idx_i], elem_snaps[idx_i])
                for idx_i in range(before)
            ]
            starred_node = t_elts[star_idx]
            assert isinstance(starred_node, ast.Starred)
            mid_p = [
                seq_p[i] if isinstance(seq_p, list) and i < len(seq_p) else None
                for i in range(before, mid_end)
            ]
            mid_f = (
                [
                    seq_f[i] if i < len(seq_f) else None
                    for i in range(before, mid_end)
                ]
                if isinstance(seq_f, list)
                else None
            )
            mid_snap = _snapshot_from_pair(mid_f, mid_p)
            out.append(_split_snapshot_for_target(starred_node.value, mid_snap))
            for idx_j in range(after):
                out.append(
                    _split_snapshot_for_target(
                        t_elts[star_idx + 1 + idx_j], elem_snaps[mid_end + idx_j]
                    )
                )
            return out
        return None

    def _prepare_rhs_for_target(target: ast.AST, value: ast.AST) -> Any:
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and not any(
                isinstance(e, ast.Starred) for e in value.elts
            ):
                t_elts = target.elts
                v_elts = value.elts
                star_indices = [i for i, e in enumerate(t_elts) if isinstance(e, ast.Starred)]
                if not star_indices:
                    if len(t_elts) != len(v_elts):
                        for sub_v in v_elts:
                            _flush_unapplied_expr_calls(sub_v)
                        return None
                    return [
                        _prepare_rhs_for_target(sub_t, sub_v)
                        for sub_t, sub_v in zip(t_elts, v_elts, strict=True)
                    ]
                if len(star_indices) == 1:
                    star_idx = star_indices[0]
                    before = star_idx
                    after = len(t_elts) - star_idx - 1
                    if len(v_elts) < before + after:
                        for sub_v in v_elts:
                            _flush_unapplied_expr_calls(sub_v)
                        return None
                    mid_end = len(v_elts) - after
                    out: list[Any] = [
                        _prepare_rhs_for_target(t_elts[idx_i], v_elts[idx_i])
                        for idx_i in range(before)
                    ]
                    starred_node = t_elts[star_idx]
                    assert isinstance(starred_node, ast.Starred)
                    mid_list = ast.List(elts=list(v_elts[before:mid_end]), ctx=ast.Load())
                    out.append(_prepare_rhs_for_target(starred_node.value, mid_list))
                    for idx_j in range(after):
                        out.append(
                            _prepare_rhs_for_target(
                                t_elts[star_idx + 1 + idx_j], v_elts[mid_end + idx_j]
                            )
                        )
                    return out
                return None
            seq_snap = _eval_rhs_snapshot(value)
            return _split_snapshot_for_target(target, seq_snap)
        return _eval_rhs_snapshot(value)

    def _apply_name_snapshot(var_name: str, snap: _RhsSnapshot) -> None:
        if snap.dict_fn is not None or snap.dict_path is not None:
            _clear_var_bindings(var_name)
            if snap.dict_fn is not None:
                dict_fn_vars[var_name] = dict(snap.dict_fn)
            if snap.dict_path is not None:
                dict_path_vars[var_name] = dict(snap.dict_path)
            return
        if snap.list_fn is not None or snap.list_path is not None:
            _clear_var_bindings(var_name)
            if snap.list_fn is not None:
                list_fn_vars[var_name] = list(snap.list_fn)
            if snap.cmd_list is not None:
                cmd_list_vars[var_name] = list(snap.cmd_list)
            if snap.list_path is not None:
                list_path_vars[var_name] = list(snap.list_path)
            return
        if snap.is_getattr:
            _clear_var_bindings(var_name)
            getattr_aliases.add(var_name)
            return
        if snap.callable_kind == "rmtree":
            _clear_var_bindings(var_name)
            rmtree_aliases.add(var_name)
            return
        if snap.callable_kind == "subprocess_cmd":
            _clear_var_bindings(var_name)
            subprocess_fn_aliases.add(var_name)
            return
        if snap.callable_kind == "os_cmd":
            _clear_var_bindings(var_name)
            os_fn_aliases.add(var_name)
            return
        if snap.callable_kind == "path_join":
            _clear_var_bindings(var_name)
            path_join_aliases.add(var_name)
            return
        if snap.import_mod == "shutil":
            _clear_var_bindings(var_name)
            shutil_aliases.add(var_name)
            return
        if snap.import_mod == "subprocess":
            _clear_var_bindings(var_name)
            subprocess_aliases.add(var_name)
            return
        if snap.import_mod == "os":
            _clear_var_bindings(var_name)
            os_aliases.add(var_name)
            return
        if snap.import_mod == "os.path":
            _clear_var_bindings(var_name)
            os_path_aliases.add(var_name)
            return
        if snap.import_mod == "builtins":
            _clear_var_bindings(var_name)
            builtins_aliases.add(var_name)
            return
        if isinstance(snap.path_val, str):
            _clear_var_bindings(var_name)
            path_vars[var_name] = snap.path_val
            return
        if isinstance(snap.path_val, int) and not isinstance(snap.path_val, bool):
            _clear_var_bindings(var_name)
            int_vars[var_name] = snap.path_val
            return
        if snap.cmd_list is not None:
            _clear_var_bindings(var_name)
            cmd_list_vars[var_name] = list(snap.cmd_list)
            return
        _clear_var_bindings(var_name)

    def _apply_prepared_binding(target: ast.AST, prepared: Any) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            if not isinstance(prepared, list) or len(prepared) != len(target.elts):
                return
            for sub_t, sub_prep in zip(target.elts, prepared, strict=True):
                if isinstance(sub_t, ast.Starred):
                    _apply_prepared_binding(sub_t.value, sub_prep)
                else:
                    _apply_prepared_binding(sub_t, sub_prep)
            return
        if isinstance(target, ast.Subscript):
            if isinstance(prepared, _RhsSnapshot):
                _apply_subscript_snapshot(target, prepared)
            return
        if isinstance(target, ast.Name) and isinstance(prepared, _RhsSnapshot):
            _apply_name_snapshot(target.id, prepared)

    def _record_binding(target: ast.AST, value: ast.AST) -> None:
        prepared = _prepare_rhs_for_target(target, value)
        _apply_prepared_binding(target, prepared)

    def _walk_container_slices(root: Any, slices: list[ast.AST]) -> Any:
        if root is None:
            return None
        cur: Any = root
        for s_node in slices:
            if isinstance(cur, dict):
                k_str = _extract_path_str(s_node)
                if k_str is None or k_str not in cur:
                    return None
                cur = cur[k_str]
            elif isinstance(cur, list):
                idx = _extract_int_node(s_node)
                if idx is None or not (-len(cur) <= idx < len(cur)):
                    return None
                cur = cur[idx]
            else:
                return None
        return cur

    def _walk_existing_container(
        root_map: Mapping[str, Any], var_name: str, slices: list[ast.AST]
    ) -> Any:
        if var_name not in root_map:
            return None
        return _walk_container_slices(root_map[var_name], slices)

    def _mirror_container_slot(
        src_cur: Any,
        dst_cur: Any,
        slices: list[ast.AST],
    ) -> Any:
        for s_node in slices:
            if isinstance(src_cur, dict) and isinstance(dst_cur, dict):
                k_str = _extract_path_str(s_node)
                if k_str is None or k_str not in src_cur:
                    return None
                src_next = src_cur[k_str]
                if isinstance(src_next, dict):
                    if k_str not in dst_cur or not isinstance(dst_cur[k_str], dict):
                        dst_cur[k_str] = {}
                elif isinstance(src_next, list):
                    if k_str not in dst_cur or not isinstance(dst_cur[k_str], list):
                        dst_cur[k_str] = [None] * len(src_next)
                else:
                    return None
                src_cur = src_next
                dst_cur = dst_cur[k_str]
            elif isinstance(src_cur, list) and isinstance(dst_cur, list):
                idx = _extract_int_node(s_node)
                if idx is None or not (-len(src_cur) <= idx < len(src_cur)):
                    return None
                if len(dst_cur) < len(src_cur):
                    dst_cur.extend([None] * (len(src_cur) - len(dst_cur)))
                src_next = src_cur[idx]
                if isinstance(src_next, dict):
                    if not isinstance(dst_cur[idx], dict):
                        dst_cur[idx] = {}
                elif isinstance(src_next, list):
                    if not isinstance(dst_cur[idx], list):
                        dst_cur[idx] = [None] * len(src_next)
                else:
                    return None
                src_cur = src_next
                dst_cur = dst_cur[idx]
            else:
                return None
        return dst_cur

    def _mirror_nested_slot(
        var_name: str,
        slices: list[ast.AST],
        *,
        src_list_vars: dict[str, list[Any]],
        src_dict_vars: dict[str, dict[str, Any]],
        dst_list_vars: dict[str, list[Any]],
        dst_dict_vars: dict[str, dict[str, Any]],
    ) -> Any:
        if var_name in src_list_vars:
            src_cur: Any = src_list_vars[var_name]
            if var_name not in dst_list_vars:
                dst_list_vars[var_name] = [None] * len(src_cur)
            dst_cur: Any = dst_list_vars[var_name]
        elif var_name in src_dict_vars:
            src_cur = src_dict_vars[var_name]
            if var_name not in dst_dict_vars:
                dst_dict_vars[var_name] = {}
            dst_cur = dst_dict_vars[var_name]
        else:
            return None
        return _mirror_container_slot(src_cur, dst_cur, slices)

    def _apply_single_dict_setdefault(
        path_dict: Any, fn_dict: Any, call_node: ast.Call
    ) -> tuple[Any, Any]:
        if not call_node.args:
            return None, None
        k_str = _extract_path_str(call_node.args[0])
        _flush_unapplied_expr_calls(call_node.args[0])
        default_node: ast.AST | None = call_node.args[1] if len(call_node.args) >= 2 else None
        if default_node is None:
            for kw in call_node.keywords:
                if kw.arg == "default":
                    default_node = kw.value
                    break
        if k_str is None:
            if default_node is not None:
                _flush_unapplied_expr_calls(default_node)
            return None, None
        res_p: Any = None
        res_f: Any = None
        key_existed = (isinstance(path_dict, dict) and k_str in path_dict) or (
            isinstance(fn_dict, dict) and k_str in fn_dict
        )
        if isinstance(path_dict, dict):
            if k_str in path_dict:
                raw_p = path_dict[k_str]
                res_p = None if raw_p is _NON_STR_VAL else raw_p
            elif not key_existed and default_node is not None:
                p_val = _resolve_path_node(default_node)
                if isinstance(p_val, dict):
                    p_val = dict(p_val)
                elif isinstance(p_val, list):
                    p_val = list(p_val)
                if p_val is not None:
                    path_dict[k_str] = p_val
                    res_p = p_val
                else:
                    path_dict[k_str] = _NON_STR_VAL
            elif not key_existed:
                path_dict[k_str] = _NON_STR_VAL
        if isinstance(fn_dict, dict):
            if k_str in fn_dict:
                res_f = fn_dict[k_str]
            elif not key_existed and default_node is not None:
                f_val = _resolve_fn_container(default_node)
                if isinstance(f_val, dict):
                    f_val = dict(f_val)
                elif isinstance(f_val, list):
                    f_val = list(f_val)
                if f_val is not None:
                    fn_dict[k_str] = f_val
                    res_f = f_val
        if default_node is not None:
            _flush_unapplied_expr_calls(default_node)
        return res_p, res_f

    def _apply_dict_setdefault_checked(
        recv_node: ast.AST, call_node: ast.Call
    ) -> tuple[bool, Any, Any]:
        call_id = id(call_node)
        if call_id in applied_setdefault_results:
            res_p, res_f = applied_setdefault_results[call_id]
            return (call_id not in applied_setdefault_untracked), res_p, res_f
        path_dict, fn_dict, _ = _resolve_mutable_containers(recv_node, create_dict=True)
        if not isinstance(path_dict, dict) and not isinstance(fn_dict, dict):
            applied_setdefault_results[call_id] = (None, None)
            applied_setdefault_untracked.add(call_id)
            return False, None, None
        res_p, res_f = _apply_single_dict_setdefault(path_dict, fn_dict, call_node)
        applied_setdefault_results[call_id] = (res_p, res_f)
        return True, res_p, res_f

    def _apply_dict_setdefault(
        recv_node: ast.AST, call_node: ast.Call
    ) -> tuple[Any, Any]:
        _, res_p, res_f = _apply_dict_setdefault_checked(recv_node, call_node)
        return res_p, res_f

    def _resolve_mutable_containers(
        recv_node: ast.AST,
        *,
        create_list: bool = False,
        create_dict: bool = False,
    ) -> tuple[Any, Any, str | None]:
        if isinstance(recv_node, ast.Name):
            var_name = recv_node.id
            path_c: Any = (
                list_path_vars[var_name]
                if var_name in list_path_vars
                else dict_path_vars.get(var_name)
            )
            fn_c: Any = (
                list_fn_vars[var_name]
                if var_name in list_fn_vars
                else dict_fn_vars.get(var_name)
            )
            if path_c is None:
                if create_list and isinstance(fn_c, list):
                    path_c = list_path_vars.setdefault(var_name, [None] * len(fn_c))
                elif create_list:
                    path_c = list_path_vars.setdefault(var_name, [])
                elif create_dict:
                    path_c = dict_path_vars.setdefault(var_name, {})
            if fn_c is None:
                if create_list and isinstance(path_c, list):
                    fn_c = list_fn_vars.setdefault(var_name, [None] * len(path_c))
                elif create_dict:
                    fn_c = dict_fn_vars.setdefault(var_name, {})
            cmd_name = var_name if var_name in cmd_list_vars else None
            return path_c, fn_c, cmd_name
        if isinstance(recv_node, ast.Subscript):
            base, slices = _unwrap_subscripts(recv_node)
            if not slices:
                return None, None, None
            if isinstance(base, ast.Name):
                var_name = base.id
                base_path: Any = (
                    list_path_vars[var_name]
                    if var_name in list_path_vars
                    else dict_path_vars.get(var_name)
                )
                base_fn: Any = (
                    list_fn_vars[var_name]
                    if var_name in list_fn_vars
                    else dict_fn_vars.get(var_name)
                )
            elif _is_setdefault_call(base):
                base_path, base_fn, _ = _resolve_mutable_containers(
                    base, create_list=True, create_dict=True
                )
            else:
                return None, None, None
            path_c = _walk_container_slices(base_path, slices)
            fn_c = _walk_container_slices(base_fn, slices)
            if fn_c is None and (
                (create_list and isinstance(path_c, list))
                or (create_dict and isinstance(path_c, dict))
            ):
                if isinstance(base, ast.Name):
                    fn_c = _mirror_nested_slot(
                        base.id,
                        slices,
                        src_list_vars=list_path_vars,
                        src_dict_vars=dict_path_vars,
                        dst_list_vars=list_fn_vars,
                        dst_dict_vars=dict_fn_vars,
                    )
                elif base_fn is not None:
                    fn_c = _mirror_container_slot(base_path, base_fn, slices)
            if (path_c is None or path_c is _NON_STR_VAL) and (
                (create_list and isinstance(fn_c, list))
                or (create_dict and isinstance(fn_c, dict))
            ):
                if isinstance(base, ast.Name):
                    path_c = _mirror_nested_slot(
                        base.id,
                        slices,
                        src_list_vars=list_fn_vars,
                        src_dict_vars=dict_fn_vars,
                        dst_list_vars=list_path_vars,
                        dst_dict_vars=dict_path_vars,
                    )
                elif base_path is not None:
                    path_c = _mirror_container_slot(base_fn, base_path, slices)
            return path_c, fn_c, None
        if (
            isinstance(recv_node, ast.Call)
            and isinstance(recv_node.func, ast.Attribute)
            and recv_node.func.attr == "setdefault"
            and recv_node.args
        ):
            sd_calls: list[ast.Call] = []
            cur_recv: ast.AST = recv_node
            while (
                isinstance(cur_recv, ast.Call)
                and isinstance(cur_recv.func, ast.Attribute)
                and cur_recv.func.attr == "setdefault"
                and cur_recv.args
            ):
                sd_calls.append(cur_recv)
                cur_recv = cur_recv.func.value
            sd_calls.reverse()
            path_c, fn_c, _ = _resolve_mutable_containers(cur_recv, create_dict=True)
            last_parent_path: Any = None
            last_parent_fn: Any = None
            last_sd_call: ast.Call | None = None
            for idx_sd, sd_call in enumerate(sd_calls):
                parent_path = path_c
                parent_fn = fn_c
                call_id = id(sd_call)
                if call_id in applied_setdefault_results:
                    path_c, fn_c = applied_setdefault_results[call_id]
                else:
                    path_c, fn_c = _apply_single_dict_setdefault(path_c, fn_c, sd_call)
                    applied_setdefault_results[call_id] = (path_c, fn_c)
                    if not isinstance(parent_path, dict) and not isinstance(parent_fn, dict):
                        applied_setdefault_untracked.add(call_id)
                is_intermediate = idx_sd < len(sd_calls) - 1
                if is_intermediate or create_dict:
                    if isinstance(path_c, dict) and fn_c is None and isinstance(parent_fn, dict):
                        k_str = _extract_path_str(sd_call.args[0])
                        if k_str is not None:
                            if k_str not in parent_fn or not isinstance(parent_fn[k_str], dict):
                                parent_fn[k_str] = {}
                            fn_c = parent_fn[k_str]
                            applied_setdefault_results[call_id] = (path_c, fn_c)
                    elif (
                        (path_c is None or path_c is _NON_STR_VAL)
                        and isinstance(fn_c, dict)
                        and isinstance(parent_path, dict)
                    ):
                        k_str = _extract_path_str(sd_call.args[0])
                        if k_str is not None:
                            if k_str not in parent_path or not isinstance(
                                parent_path[k_str], dict
                            ):
                                parent_path[k_str] = {}
                            path_c = parent_path[k_str]
                            applied_setdefault_results[call_id] = (path_c, fn_c)
                last_parent_path = parent_path
                last_parent_fn = parent_fn
                last_sd_call = sd_call
            if create_list and last_sd_call is not None:
                last_call_id = id(last_sd_call)
                if (
                    isinstance(path_c, list)
                    and fn_c is None
                    and isinstance(last_parent_fn, dict)
                ):
                    k_str = _extract_path_str(last_sd_call.args[0])
                    if k_str is not None:
                        existing_fn = (
                            last_parent_fn[k_str]
                            if k_str in last_parent_fn
                            and isinstance(last_parent_fn[k_str], list)
                            else None
                        )
                        if existing_fn is None or len(existing_fn) < len(path_c):
                            base_fn = list(existing_fn) if existing_fn is not None else []
                            last_parent_fn[k_str] = base_fn + [None] * (len(path_c) - len(base_fn))
                        fn_c = last_parent_fn[k_str]
                        applied_setdefault_results[last_call_id] = (path_c, fn_c)
                elif (
                    (path_c is None or path_c is _NON_STR_VAL)
                    and isinstance(fn_c, list)
                    and isinstance(last_parent_path, dict)
                ):
                    k_str = _extract_path_str(last_sd_call.args[0])
                    if k_str is not None:
                        existing_p = (
                            last_parent_path[k_str]
                            if k_str in last_parent_path
                            and isinstance(last_parent_path[k_str], list)
                            else None
                        )
                        if existing_p is None or len(existing_p) < len(fn_c):
                            base_p = list(existing_p) if existing_p is not None else []
                            last_parent_path[k_str] = base_p + [None] * (len(fn_c) - len(base_p))
                        path_c = last_parent_path[k_str]
                        applied_setdefault_results[last_call_id] = (path_c, fn_c)
            return path_c, fn_c, None
        return None, None, None

    def _apply_pop_call(call_node: ast.Call, *, mode: Literal["path", "fn", "both"]) -> Any:
        if not _is_pop_call(call_node):
            return None
        call_id = id(call_node)
        need_path = call_id not in popped_path_calls
        need_fn = call_id not in popped_fn_calls

        if not need_path and not need_fn:
            return popped_fn_calls[call_id] if mode == "fn" else popped_path_calls[call_id]

        assert isinstance(call_node.func, ast.Attribute)
        recv = call_node.func.value
        path_c, fn_c, cmd_name = _resolve_mutable_containers(recv)

        is_temp_path = False
        if path_c is None and fn_c is None:
            if need_path:
                tmp_p = _resolve_path_node(recv)
                if isinstance(tmp_p, dict):
                    path_c = dict(tmp_p)
                    is_temp_path = True
                elif isinstance(tmp_p, list):
                    path_c = list(tmp_p)
                    is_temp_path = True
            if need_fn:
                tmp_f = _resolve_fn_container(recv)
                if isinstance(tmp_f, dict):
                    fn_c = dict(tmp_f)
                elif isinstance(tmp_f, list):
                    fn_c = list(tmp_f)

        is_dict = isinstance(path_c, dict) or isinstance(fn_c, dict)
        is_list = (not is_dict) and (isinstance(path_c, list) or isinstance(fn_c, list))

        if is_dict:
            if not call_node.args:
                if need_path:
                    popped_path_calls[call_id] = None
                if need_fn:
                    popped_fn_calls[call_id] = None
                return None
            k_str = _extract_path_str(call_node.args[0])
            if k_str is None:
                if need_path:
                    popped_path_calls[call_id] = None
                if need_fn:
                    popped_fn_calls[call_id] = None
                return None
            key_existed = popped_dict_key_existed.get(call_id)
            if key_existed is None:
                key_existed = (isinstance(path_c, dict) and k_str in path_c) or (
                    isinstance(fn_c, dict) and k_str in fn_c
                )
                popped_dict_key_existed[call_id] = key_existed
            default_node: ast.AST | None = call_node.args[1] if len(call_node.args) >= 2 else None
            if need_path:
                res_p: Any = None
                if isinstance(path_c, dict) and k_str in path_c:
                    raw_p = path_c.pop(k_str)
                    res_p = None if raw_p is _NON_STR_VAL else raw_p
                elif not key_existed and default_node is not None:
                    res_p = _resolve_path_node(default_node)
                popped_path_calls[call_id] = res_p
            if need_fn:
                res_f: Any = None
                if isinstance(fn_c, dict) and k_str in fn_c:
                    res_f = fn_c.pop(k_str)
                elif not key_existed and default_node is not None:
                    res_f = _resolve_fn_container(default_node)
                popped_fn_calls[call_id] = res_f
        elif is_list:
            if len(call_node.args) > 1:
                if need_path:
                    popped_path_calls[call_id] = None
                if need_fn:
                    popped_fn_calls[call_id] = None
                return None
            idx = -1 if not call_node.args else _extract_int_node(call_node.args[0])
            if idx is None:
                if need_path:
                    popped_path_calls[call_id] = None
                if need_fn:
                    popped_fn_calls[call_id] = None
                return None
            if need_path:
                res_p = None
                if isinstance(path_c, list) and -len(path_c) <= idx < len(path_c):
                    res_p = path_c.pop(idx)
                if (
                    not is_temp_path
                    and cmd_name is not None
                    and cmd_name in cmd_list_vars
                    and -len(cmd_list_vars[cmd_name]) <= idx < len(cmd_list_vars[cmd_name])
                ):
                    cmd_list_vars[cmd_name].pop(idx)
                popped_path_calls[call_id] = res_p
            if need_fn:
                res_f = None
                if isinstance(fn_c, list) and -len(fn_c) <= idx < len(fn_c):
                    res_f = fn_c.pop(idx)
                popped_fn_calls[call_id] = res_f
        else:
            if need_path:
                popped_path_calls[call_id] = None
            if need_fn:
                popped_fn_calls[call_id] = None

        return popped_fn_calls[call_id] if mode == "fn" else popped_path_calls[call_id]

    def _apply_popitem_call(
        call_node: ast.Call, *, mode: Literal["path", "fn", "both"]
    ) -> list[Any] | None:
        if not _is_popitem_call(call_node):
            return None
        call_id = id(call_node)
        need_path = call_id not in popitem_path_calls
        need_fn = call_id not in popitem_fn_calls

        if not need_path and not need_fn:
            return popitem_fn_calls[call_id] if mode == "fn" else popitem_path_calls[call_id]

        assert isinstance(call_node.func, ast.Attribute)
        recv = call_node.func.value
        path_c, fn_c, _ = _resolve_mutable_containers(recv)
        if path_c is None and fn_c is None:
            tmp_p = _resolve_path_node(recv)
            if isinstance(tmp_p, dict):
                path_c = dict(tmp_p)
            tmp_f = _resolve_fn_container(recv)
            if isinstance(tmp_f, dict):
                fn_c = dict(tmp_f)

        if isinstance(path_c, dict) and path_c:
            last_k, raw_p = path_c.popitem()
            res_p = None if raw_p is _NON_STR_VAL else raw_p
            res_f = fn_c.pop(last_k, None) if isinstance(fn_c, dict) else None
            popitem_path_calls[call_id] = [last_k, res_p]
            popitem_fn_calls[call_id] = [None, res_f] if res_f is not None else None
        elif isinstance(fn_c, dict) and fn_c:
            last_k, res_f = fn_c.popitem()
            popitem_path_calls[call_id] = [last_k, None]
            popitem_fn_calls[call_id] = [None, res_f] if res_f is not None else None
        else:
            popitem_path_calls[call_id] = None
            popitem_fn_calls[call_id] = None

        return popitem_fn_calls[call_id] if mode == "fn" else popitem_path_calls[call_id]

    def _untrack_mutable_container(recv_node: ast.AST) -> None:
        if isinstance(recv_node, ast.Name):
            var_name = recv_node.id
            list_path_vars.pop(var_name, None)
            list_fn_vars.pop(var_name, None)
            cmd_list_vars.pop(var_name, None)
            return
        if isinstance(recv_node, ast.Subscript):
            base, slices = _unwrap_subscripts(recv_node)
            if not slices:
                return
            if isinstance(base, ast.Name):
                b_path: Any = (
                    list_path_vars[base.id]
                    if base.id in list_path_vars
                    else dict_path_vars.get(base.id)
                )
                b_fn: Any = (
                    list_fn_vars[base.id]
                    if base.id in list_fn_vars
                    else dict_fn_vars.get(base.id)
                )
            elif _is_setdefault_call(base):
                b_path, b_fn, _ = _resolve_mutable_containers(base)
            else:
                return
            p_parent = _walk_container_slices(b_path, slices[:-1])
            f_parent = _walk_container_slices(b_fn, slices[:-1])
            last_s = slices[-1]
            if isinstance(p_parent, dict) or isinstance(f_parent, dict):
                last_k = _extract_path_str(last_s)
                if last_k is not None:
                    if isinstance(p_parent, dict):
                        p_parent[last_k] = _NON_STR_VAL
                    if isinstance(f_parent, dict):
                        f_parent.pop(last_k, None)
            elif isinstance(p_parent, list) or isinstance(f_parent, list):
                idx = _extract_int_node(last_s)
                if idx is not None:
                    if isinstance(p_parent, list) and -len(p_parent) <= idx < len(p_parent):
                        p_parent[idx] = None
                    if isinstance(f_parent, list) and -len(f_parent) <= idx < len(f_parent):
                        f_parent[idx] = None
            return
        if _is_setdefault_call(recv_node):
            assert isinstance(recv_node, ast.Call)
            assert isinstance(recv_node.func, ast.Attribute)
            parent_p, parent_f, _ = _resolve_mutable_containers(recv_node.func.value)
            if recv_node.args:
                k_str = _extract_path_str(recv_node.args[0])
                if k_str is not None:
                    if isinstance(parent_p, dict):
                        parent_p[k_str] = _NON_STR_VAL
                    if isinstance(parent_f, dict):
                        parent_f.pop(k_str, None)

    def _apply_dict_update_call(
        path_dict: dict[str, Any] | None,
        fn_dict: dict[str, Any] | None,
        args: Sequence[ast.AST],
        keywords: Sequence[ast.keyword],
    ) -> None:
        if args:
            arg0 = args[0]
            arg0_path_val = _resolve_path_node(arg0)
            fn_val = _resolve_fn_container(arg0) if fn_dict is not None else None
            if path_dict is not None:
                if isinstance(arg0_path_val, Mapping):
                    path_dict.update(arg0_path_val)
                elif isinstance(arg0_path_val, list):
                    for pair in arg0_path_val:
                        if (
                            isinstance(pair, (list, tuple))
                            and len(pair) == 2
                            and isinstance(pair[0], str)
                        ):
                            if pair[1] is not None:
                                path_dict[pair[0]] = pair[1]
                            else:
                                path_dict[pair[0]] = _NON_STR_VAL
            if fn_dict is not None:
                if isinstance(arg0_path_val, Mapping) or isinstance(fn_val, Mapping):
                    _merge_dict_mapping(None, fn_dict, arg0_path_val, fn_val)
                elif isinstance(arg0, (ast.List, ast.Tuple)):
                    for elt in arg0.elts:
                        if isinstance(elt, (ast.List, ast.Tuple)) and len(elt.elts) == 2:
                            k_str = _extract_path_str(elt.elts[0])
                            _flush_unapplied_expr_calls(elt.elts[0])
                            if k_str is not None:
                                v_fn = _resolve_fn_container(elt.elts[1])
                                if isinstance(v_fn, dict):
                                    fn_dict[k_str] = dict(v_fn)
                                elif isinstance(v_fn, list):
                                    fn_dict[k_str] = list(v_fn)
                                elif v_fn is not None:
                                    fn_dict[k_str] = v_fn
                                else:
                                    fn_dict.pop(k_str, None)
                            _flush_unapplied_expr_calls(elt.elts[1])
                elif isinstance(fn_val, list) and isinstance(arg0_path_val, list):
                    for p_pair, f_pair in zip(arg0_path_val, fn_val, strict=False):
                        if (
                            isinstance(p_pair, (list, tuple))
                            and len(p_pair) == 2
                            and isinstance(p_pair[0], str)
                        ):
                            k_str = p_pair[0]
                            v_fn = (
                                f_pair[1]
                                if isinstance(f_pair, (list, tuple)) and len(f_pair) == 2
                                else None
                            )
                            if isinstance(v_fn, dict):
                                fn_dict[k_str] = dict(v_fn)
                            elif isinstance(v_fn, list):
                                fn_dict[k_str] = list(v_fn)
                            elif v_fn is not None:
                                fn_dict[k_str] = v_fn
                            else:
                                fn_dict.pop(k_str, None)
                elif fn_val is None and isinstance(arg0_path_val, list):
                    for p_pair in arg0_path_val:
                        if (
                            isinstance(p_pair, (list, tuple))
                            and len(p_pair) == 2
                            and isinstance(p_pair[0], str)
                        ):
                            fn_dict.pop(p_pair[0], None)
            _flush_unapplied_expr_calls(arg0)
        for kw in keywords:
            if kw.arg is None:
                unpacked_p = _resolve_path_node(kw.value)
                unpacked_f = _resolve_fn_container(kw.value)
                _merge_dict_mapping(path_dict, fn_dict, unpacked_p, unpacked_f)
                _flush_unapplied_expr_calls(kw.value)
            else:
                if path_dict is not None:
                    p_val = _resolve_path_node(kw.value)
                    if isinstance(p_val, dict):
                        path_dict[kw.arg] = dict(p_val)
                    elif isinstance(p_val, list):
                        path_dict[kw.arg] = list(p_val)
                    elif p_val is not None:
                        path_dict[kw.arg] = p_val
                    else:
                        path_dict[kw.arg] = _NON_STR_VAL
                if fn_dict is not None:
                    f_val = _resolve_fn_container(kw.value)
                    if isinstance(f_val, dict):
                        fn_dict[kw.arg] = dict(f_val)
                    elif isinstance(f_val, list):
                        fn_dict[kw.arg] = list(f_val)
                    elif f_val is not None:
                        fn_dict[kw.arg] = f_val
                    else:
                        fn_dict.pop(kw.arg, None)
                _flush_unapplied_expr_calls(kw.value)

    def _apply_path_subscript_write(
        cur: Any, slices: list[ast.AST], path_val: Any, *, fn_val: Any = None
    ) -> bool:
        ok_walk = True
        for s_node in slices[:-1]:
            if isinstance(cur, dict):
                k_str = _extract_path_str(s_node)
                if k_str is None:
                    ok_walk = False
                    break
                nxt = cur.get(k_str)
                if not isinstance(nxt, (dict, list)):
                    nxt = {}
                    cur[k_str] = nxt
                cur = nxt
            elif isinstance(cur, list):
                idx = _extract_int_node(s_node)
                if idx is None or not (-len(cur) <= idx < len(cur)):
                    ok_walk = False
                    break
                cur = cur[idx]
            else:
                ok_walk = False
                break
        if ok_walk:
            last_s = slices[-1]
            if isinstance(cur, dict):
                last_k = _extract_path_str(last_s)
                if last_k is not None:
                    if path_val is not None:
                        cur[last_k] = path_val
                    else:
                        cur[last_k] = _NON_STR_VAL
            elif isinstance(cur, list):
                if isinstance(last_s, ast.Slice):
                    slice_obj = _extract_ast_slice_obj(
                        last_s,
                        int_resolver=_extract_int_node,
                        expr_flusher=_flush_unapplied_expr_calls,
                    )
                    if slice_obj is not None:
                        rhs_p, _ = _slice_rhs_lists(path_val, fn_val)
                        if rhs_p is None:
                            return True
                        new_len = _slice_assign_new_len(len(cur), slice_obj, len(rhs_p))
                        if new_len is not None and new_len > _MAX_TRACKED_LIST_LEN:
                            return True
                        _assign_list_slice(cur, slice_obj, rhs_p)
                else:
                    idx = _extract_int_node(last_s)
                    if idx is not None and -len(cur) <= idx < len(cur):
                        cur[idx] = path_val
        return False

    def _apply_fn_subscript_write(
        cur_fn: Any, slices: list[ast.AST], fn_val: Any, *, path_val: Any = None
    ) -> bool:
        ok_fn = True
        for s_node in slices[:-1]:
            if isinstance(cur_fn, dict):
                k_str = _extract_path_str(s_node)
                if k_str is None:
                    ok_fn = False
                    break
                nxt_fn = cur_fn.get(k_str)
                if not isinstance(nxt_fn, (dict, list)):
                    nxt_fn = {}
                    cur_fn[k_str] = nxt_fn
                cur_fn = nxt_fn
            elif isinstance(cur_fn, list):
                idx = _extract_int_node(s_node)
                if idx is None or not (-len(cur_fn) <= idx < len(cur_fn)):
                    ok_fn = False
                    break
                cur_fn = cur_fn[idx]
            else:
                ok_fn = False
                break
        if ok_fn:
            last_s = slices[-1]
            if isinstance(cur_fn, dict):
                last_k = _extract_path_str(last_s)
                if last_k is not None:
                    if fn_val is not None:
                        cur_fn[last_k] = fn_val
                    else:
                        cur_fn.pop(last_k, None)
            elif isinstance(cur_fn, list):
                if isinstance(last_s, ast.Slice):
                    slice_obj = _extract_ast_slice_obj(
                        last_s,
                        int_resolver=_extract_int_node,
                        expr_flusher=_flush_unapplied_expr_calls,
                    )
                    if slice_obj is not None:
                        _, rhs_f = _slice_rhs_lists(path_val, fn_val)
                        if rhs_f is None:
                            return True
                        new_len = _slice_assign_new_len(len(cur_fn), slice_obj, len(rhs_f))
                        if new_len is not None and new_len > _MAX_TRACKED_LIST_LEN:
                            return True
                        _assign_list_slice(cur_fn, slice_obj, rhs_f)
                else:
                    idx = _extract_int_node(last_s)
                    if idx is not None and -len(cur_fn) <= idx < len(cur_fn):
                        cur_fn[idx] = fn_val
        return False

    def _apply_subscript_snapshot(tgt: ast.Subscript, snap: _RhsSnapshot) -> None:
        base, slices = _unwrap_subscripts(tgt)
        if not slices or (not isinstance(base, ast.Name) and not _is_setdefault_call(base)):
            return
        path_val = snap.path_val
        if isinstance(path_val, dict):
            path_val = dict(path_val)
        elif isinstance(path_val, list):
            path_val = list(path_val)

        fn_val = snap.fn_val
        if isinstance(fn_val, dict):
            fn_val = dict(fn_val)
        elif isinstance(fn_val, list):
            fn_val = list(fn_val)

        if _is_setdefault_call(base):
            base_path, base_fn, _ = _resolve_mutable_containers(
                base, create_list=True, create_dict=True
            )
            if (
                len(slices) > 1
                and isinstance(base_path, (dict, list))
                and isinstance(base_fn, (dict, list))
            ):
                _mirror_container_slot(base_fn, base_path, slices[:-1])
                _mirror_container_slot(base_path, base_fn, slices[:-1])
            if isinstance(base_path, (dict, list)) and _apply_path_subscript_write(
                base_path, slices, path_val, fn_val=fn_val
            ):
                _untrack_mutable_container(tgt.value)
                return
            if isinstance(base_fn, (dict, list)) and _apply_fn_subscript_write(
                base_fn, slices, fn_val, path_val=path_val
            ):
                _untrack_mutable_container(tgt.value)
            return

        assert isinstance(base, ast.Name)
        var_name = base.id
        if (
            var_name not in list_path_vars
            and var_name in list_fn_vars
            and (path_val is not None or fn_val is not None)
        ):
            list_path_vars[var_name] = [None] * len(list_fn_vars[var_name])
        if (
            var_name not in list_fn_vars
            and var_name in list_path_vars
            and (fn_val is not None or path_val is not None)
        ):
            list_fn_vars[var_name] = [None] * len(list_path_vars[var_name])
        if (var_name in list_fn_vars or var_name in dict_fn_vars) and len(slices) > 1:
            _mirror_nested_slot(
                var_name,
                slices[:-1],
                src_list_vars=list_fn_vars,
                src_dict_vars=dict_fn_vars,
                dst_list_vars=list_path_vars,
                dst_dict_vars=dict_path_vars,
            )
        if (var_name in list_path_vars or var_name in dict_path_vars) and len(slices) > 1:
            _mirror_nested_slot(
                var_name,
                slices[:-1],
                src_list_vars=list_path_vars,
                src_dict_vars=dict_path_vars,
                dst_list_vars=list_fn_vars,
                dst_dict_vars=dict_fn_vars,
            )

        rhs_slice_p, rhs_slice_f = _slice_rhs_lists(path_val, fn_val)

        if len(slices) == 1 and var_name in list_path_vars:
            lst = list_path_vars[var_name]
            if isinstance(slices[0], ast.Slice):
                slice_obj = _extract_ast_slice_obj(
                    slices[0],
                    int_resolver=_extract_int_node,
                    expr_flusher=_flush_unapplied_expr_calls,
                )
                if slice_obj is not None:
                    if rhs_slice_p is None:
                        _untrack_mutable_container(base)
                        return
                    new_p_len = _slice_assign_new_len(len(lst), slice_obj, len(rhs_slice_p))
                    if new_p_len is not None and new_p_len > _MAX_TRACKED_LIST_LEN:
                        _untrack_mutable_container(base)
                        return
                    if (
                        _assign_list_slice(lst, slice_obj, rhs_slice_p)
                        and var_name in cmd_list_vars
                        and not (
                            all(isinstance(x, str) for x in rhs_slice_p)
                            and _assign_list_slice(
                                cmd_list_vars[var_name], slice_obj, rhs_slice_p
                            )
                        )
                    ):
                        cmd_list_vars.pop(var_name, None)
            else:
                idx = _extract_int_node(slices[0])
                if idx is not None and -len(lst) <= idx < len(lst):
                    lst[idx] = path_val
                    if var_name in cmd_list_vars:
                        if isinstance(path_val, str):
                            cmd_list_vars[var_name][idx] = path_val
                        else:
                            cmd_list_vars.pop(var_name, None)
        elif var_name in list_path_vars or var_name in dict_path_vars or len(slices) == 1:
            cur: Any = (
                list_path_vars[var_name]
                if var_name in list_path_vars
                else dict_path_vars.setdefault(var_name, {})
            )
            if _apply_path_subscript_write(cur, slices, path_val, fn_val=fn_val):
                _untrack_mutable_container(tgt.value)
                return

        if len(slices) == 1 and var_name in list_fn_vars:
            fn_lst = list_fn_vars[var_name]
            if isinstance(slices[0], ast.Slice):
                slice_obj = _extract_ast_slice_obj(
                    slices[0],
                    int_resolver=_extract_int_node,
                    expr_flusher=_flush_unapplied_expr_calls,
                )
                if slice_obj is not None and rhs_slice_f is not None:
                    new_f_len = _slice_assign_new_len(len(fn_lst), slice_obj, len(rhs_slice_f))
                    if new_f_len is not None and new_f_len > _MAX_TRACKED_LIST_LEN:
                        _untrack_mutable_container(base)
                        return
                    _assign_list_slice(fn_lst, slice_obj, rhs_slice_f)
            else:
                idx = _extract_int_node(slices[0])
                if idx is not None and -len(fn_lst) <= idx < len(fn_lst):
                    fn_lst[idx] = fn_val
        elif var_name in dict_fn_vars or var_name in list_fn_vars or fn_val is not None:
            cur_fn: Any = (
                list_fn_vars[var_name]
                if var_name in list_fn_vars
                else dict_fn_vars.setdefault(var_name, {})
            )
            if _apply_fn_subscript_write(cur_fn, slices, fn_val, path_val=path_val):
                _untrack_mutable_container(tgt.value)

    def _record_subscript_mutation(tgt: ast.Subscript, value: ast.AST) -> None:
        _apply_subscript_snapshot(tgt, _eval_rhs_snapshot(value))

    def _apply_mutating_call(call_node: ast.Call) -> None:
        if not isinstance(call_node.func, ast.Attribute):
            return
        recv = call_node.func.value
        method = call_node.func.attr
        if method == "setdefault" and call_node.args:
            _apply_dict_setdefault(recv, call_node)
            return
        if method == "pop" and not call_node.keywords and len(call_node.args) <= 2:
            _apply_pop_call(call_node, mode="both")
            return
        if method == "popitem" and not call_node.args and not call_node.keywords:
            _apply_popitem_call(call_node, mode="both")
            return
        call_id = id(call_node)
        if call_id in applied_mutating_calls:
            return
        if method == "append" and len(call_node.args) == 1 and not call_node.keywords:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv, create_list=True)
            arg0 = call_node.args[0]
            val = _resolve_path_node(arg0)
            if isinstance(val, dict):
                val = dict(val)
            elif isinstance(val, list):
                val = list(val)
            fn_val = _resolve_fn_container(arg0)
            if isinstance(fn_val, dict):
                fn_val = dict(fn_val)
            elif isinstance(fn_val, list):
                fn_val = list(fn_val)
            _flush_unapplied_expr_calls(arg0)
            if (isinstance(path_c, list) and len(path_c) >= _MAX_TRACKED_LIST_LEN) or (
                isinstance(fn_c, list) and len(fn_c) >= _MAX_TRACKED_LIST_LEN
            ):
                _untrack_mutable_container(recv)
                return
            if isinstance(path_c, list):
                path_c.append(val)
            if cmd_name is not None:
                if isinstance(val, str):
                    cmd_list_vars[cmd_name].append(val)
                else:
                    cmd_list_vars.pop(cmd_name, None)
            if isinstance(fn_c, list):
                fn_c.append(fn_val)
        elif method == "extend" and len(call_node.args) == 1 and not call_node.keywords:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv, create_list=True)
            arg0 = call_node.args[0]
            val = _resolve_path_node(arg0)
            fn_val = _resolve_fn_container(arg0)
            _flush_unapplied_expr_calls(arg0)
            rhs_ext_p, rhs_ext_f = _slice_rhs_lists(val, fn_val)
            if rhs_ext_p is None and rhs_ext_f is None:
                _untrack_mutable_container(recv)
                return
            if (
                rhs_ext_p is not None
                and isinstance(path_c, list)
                and len(path_c) + len(rhs_ext_p) > _MAX_TRACKED_LIST_LEN
            ) or (
                rhs_ext_f is not None
                and isinstance(fn_c, list)
                and len(fn_c) + len(rhs_ext_f) > _MAX_TRACKED_LIST_LEN
            ):
                _untrack_mutable_container(recv)
                return
            if rhs_ext_p is not None and isinstance(path_c, list):
                path_c.extend(rhs_ext_p)
                if cmd_name is not None:
                    if all(isinstance(x, str) for x in rhs_ext_p):
                        cmd_list_vars[cmd_name].extend(rhs_ext_p)
                    else:
                        cmd_list_vars.pop(cmd_name, None)
            if rhs_ext_f is not None and isinstance(fn_c, list):
                fn_c.extend(rhs_ext_f)
        elif method == "insert" and len(call_node.args) == 2 and not call_node.keywords:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv, create_list=True)
            idx = _extract_int_node(call_node.args[0])
            _flush_unapplied_expr_calls(call_node.args[0])
            arg1 = call_node.args[1]
            val = _resolve_path_node(arg1)
            if isinstance(val, dict):
                val = dict(val)
            elif isinstance(val, list):
                val = list(val)
            fn_val = _resolve_fn_container(arg1)
            if isinstance(fn_val, dict):
                fn_val = dict(fn_val)
            elif isinstance(fn_val, list):
                fn_val = list(fn_val)
            _flush_unapplied_expr_calls(arg1)
            if (isinstance(path_c, list) and len(path_c) >= _MAX_TRACKED_LIST_LEN) or (
                isinstance(fn_c, list) and len(fn_c) >= _MAX_TRACKED_LIST_LEN
            ):
                _untrack_mutable_container(recv)
                return
            if idx is not None:
                if isinstance(path_c, list):
                    path_c.insert(idx, val)
                if cmd_name is not None:
                    if isinstance(val, str):
                        cmd_list_vars[cmd_name].insert(idx, val)
                    else:
                        cmd_list_vars.pop(cmd_name, None)
                if isinstance(fn_c, list):
                    fn_c.insert(idx, fn_val)
        elif method == "reverse" and not call_node.args and not call_node.keywords:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv)
            if isinstance(path_c, list):
                path_c.reverse()
            if isinstance(fn_c, list):
                fn_c.reverse()
            if cmd_name is not None and cmd_name in cmd_list_vars:
                cmd_list_vars[cmd_name].reverse()
        elif method == "sort" and not call_node.args:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv)
            key_ok = True
            rev_val = False
            kw_ok = True
            for kw in call_node.keywords:
                _flush_unapplied_expr_calls(kw.value)
                if kw.arg == "key":
                    if not _is_ast_none(kw.value):
                        key_ok = False
                elif kw.arg == "reverse":
                    b_val = _extract_bool_node(kw.value)
                    if b_val is not None:
                        rev_val = b_val
                    else:
                        kw_ok = False
                else:
                    kw_ok = False
            if not key_ok or not kw_ok:
                _untrack_mutable_container(recv)
            elif isinstance(path_c, list):
                if isinstance(fn_c, list) and any(x is not None for x in fn_c):
                    _untrack_mutable_container(recv)
                elif all(isinstance(x, str) for x in path_c):
                    path_c.sort(reverse=rev_val)
                    if cmd_name is not None and cmd_name in cmd_list_vars:
                        cmd_list_vars[cmd_name].sort(reverse=rev_val)
                elif all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in path_c):
                    path_c.sort(reverse=rev_val)
                    if cmd_name is not None:
                        cmd_list_vars.pop(cmd_name, None)
                else:
                    _untrack_mutable_container(recv)
            elif isinstance(fn_c, list) and fn_c:
                _untrack_mutable_container(recv)
        elif method == "update":
            applied_mutating_calls.add(call_id)
            path_c, fn_c, _ = _resolve_mutable_containers(recv, create_dict=True)
            _apply_dict_update_call(
                path_c if isinstance(path_c, dict) else None,
                fn_c if isinstance(fn_c, dict) else None,
                call_node.args,
                call_node.keywords,
            )
        elif method == "clear" and not call_node.args and not call_node.keywords:
            applied_mutating_calls.add(call_id)
            path_c, fn_c, cmd_name = _resolve_mutable_containers(recv)
            if isinstance(path_c, (dict, list)):
                path_c.clear()
            if isinstance(fn_c, (dict, list)):
                fn_c.clear()
            if cmd_name is not None:
                cmd_list_vars[cmd_name].clear()

    def _visit_node(node: ast.AST) -> str | None:
        nonlocal truncated_by_depth
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if alias.name == "shutil":
                    shutil_aliases.add(bound)
                elif alias.name == "subprocess":
                    subprocess_aliases.add(bound)
                elif alias.name == "os":
                    os_aliases.add(bound)
                elif alias.name == "os.path":
                    if alias.asname:
                        os_path_aliases.add(alias.asname)
                    else:
                        os_aliases.add("os")
                elif alias.name == "posixpath":
                    os_path_aliases.add(bound)
                elif alias.name == "builtins":
                    builtins_aliases.add(bound)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "shutil":
                for alias in node.names:
                    if alias.name == "rmtree":
                        rmtree_aliases.add(alias.asname or "rmtree")
            elif node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _SUBPROCESS_EXEC_FUNCS:
                        subprocess_fn_aliases.add(alias.asname or alias.name)
            elif node.module == "os":
                for alias in node.names:
                    if alias.name in _OS_EXEC_FUNCS:
                        os_fn_aliases.add(alias.asname or alias.name)
                    elif alias.name == "path":
                        os_path_aliases.add(alias.asname or "path")
            elif node.module in {"os.path", "posixpath"}:
                for alias in node.names:
                    if alias.name == "join":
                        path_join_aliases.add(alias.asname or "join")
            elif node.module == "builtins":
                for alias in node.names:
                    if alias.name == "getattr":
                        getattr_aliases.add(alias.asname or "getattr")
        elif isinstance(node, ast.Assign):
            prepared_targets = [
                (tgt, _prepare_rhs_for_target(tgt, node.value))
                for tgt in node.targets
            ]
            for tgt, prepared in prepared_targets:
                _apply_prepared_binding(tgt, prepared)
        elif isinstance(node, ast.NamedExpr):
            _apply_named_expr(node)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                if isinstance(node.target, ast.Subscript):
                    _record_subscript_mutation(node.target, node.value)
                else:
                    _record_binding(node.target, node.value)
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    _clear_var_bindings(tgt.id)
                elif isinstance(tgt, ast.Subscript):
                    base, slices = _unwrap_subscripts(tgt)
                    if not slices or (
                        not isinstance(base, ast.Name) and not _is_setdefault_call(base)
                    ):
                        continue
                    if isinstance(base, ast.Name):
                        var_name = base.id
                        base_path: Any = (
                            list_path_vars[var_name]
                            if var_name in list_path_vars
                            else dict_path_vars.get(var_name)
                        )
                        base_fn: Any = (
                            list_fn_vars[var_name]
                            if var_name in list_fn_vars
                            else dict_fn_vars.get(var_name)
                        )
                        cmd_name_del: str | None = (
                            var_name
                            if len(slices) == 1 and var_name in cmd_list_vars
                            else None
                        )
                    else:
                        base_path, base_fn, _ = _resolve_mutable_containers(base)
                        cmd_name_del = None
                    cur_path = _walk_container_slices(base_path, slices[:-1])
                    cur_fn = _walk_container_slices(base_fn, slices[:-1])
                    last_s = slices[-1]
                    if isinstance(cur_path, dict) or isinstance(cur_fn, dict):
                        last_k = _extract_path_str(last_s)
                        if last_k is not None:
                            if isinstance(cur_path, dict):
                                cur_path.pop(last_k, None)
                            if isinstance(cur_fn, dict):
                                cur_fn.pop(last_k, None)
                    elif isinstance(cur_path, list) or isinstance(cur_fn, list):
                        if isinstance(last_s, ast.Slice):
                            slice_obj = _extract_ast_slice_obj(
                                last_s,
                                int_resolver=_extract_int_node,
                                expr_flusher=_flush_unapplied_expr_calls,
                            )
                            if slice_obj is not None:
                                if isinstance(cur_path, list):
                                    del cur_path[slice_obj]
                                if isinstance(cur_fn, list):
                                    del cur_fn[slice_obj]
                                if cmd_name_del is not None and cmd_name_del in cmd_list_vars:
                                    del cmd_list_vars[cmd_name_del][slice_obj]
                        else:
                            idx = _extract_int_node(last_s)
                            if idx is not None:
                                if isinstance(cur_path, list) and -len(cur_path) <= idx < len(
                                    cur_path
                                ):
                                    del cur_path[idx]
                                if isinstance(cur_fn, list) and -len(cur_fn) <= idx < len(cur_fn):
                                    del cur_fn[idx]
                                if cmd_name_del is not None and cmd_name_del in cmd_list_vars:
                                    cmd_lst = cmd_list_vars[cmd_name_del]
                                    if -len(cmd_lst) <= idx < len(cmd_lst):
                                        del cmd_lst[idx]
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id in int_vars:
                int_name = node.target.id
                lhs_int = int_vars[int_name]
                rhs_int = _extract_int_node(node.value)
                _flush_unapplied_expr_calls(node.value)
                new_int: int | None = None
                if rhs_int is not None:
                    if isinstance(node.op, ast.Add):
                        new_int = lhs_int + rhs_int
                    elif isinstance(node.op, ast.Sub):
                        new_int = lhs_int - rhs_int
                    elif isinstance(node.op, ast.Mult):
                        new_int = lhs_int * rhs_int
                    elif isinstance(node.op, ast.FloorDiv) and rhs_int != 0:
                        new_int = lhs_int // rhs_int
                if new_int is not None and abs(new_int) <= 1_000_000_000:
                    int_vars[int_name] = new_int
                else:
                    int_vars.pop(int_name, None)
            elif isinstance(node.op, ast.BitOr):
                path_c, fn_c, _ = _resolve_mutable_containers(node.target, create_dict=True)
                rhs_path = _resolve_path_node(node.value)
                rhs_fn = _resolve_fn_container(node.value)
                _flush_unapplied_expr_calls(node.value)
                _merge_dict_mapping(
                    path_c if isinstance(path_c, dict) else None,
                    fn_c if isinstance(fn_c, dict) else None,
                    rhs_path,
                    rhs_fn,
                )
            elif isinstance(node.op, ast.Add):
                if isinstance(node.target, ast.Subscript) and isinstance(
                    node.target.slice, ast.Slice
                ):
                    rhs_path = _resolve_path_node(node.value)
                    rhs_fn = _resolve_fn_container(node.value)
                    _flush_unapplied_expr_calls(node.value)
                    rhs_p, rhs_f = _slice_rhs_lists(rhs_path, rhs_fn)
                    slice_obj = _extract_ast_slice_obj(
                        node.target.slice,
                        int_resolver=_extract_int_node,
                        expr_flusher=_flush_unapplied_expr_calls,
                    )
                    if slice_obj is not None:
                        if rhs_p is None and rhs_f is None:
                            _untrack_mutable_container(node.target.value)
                            return None
                        path_c, fn_c, cmd_name = _resolve_mutable_containers(node.target.value)
                        if isinstance(path_c, list) or isinstance(fn_c, list):
                            path_c, fn_c, cmd_name = _resolve_mutable_containers(
                                node.target.value, create_list=True
                            )
                        if (
                            rhs_p is not None
                            and isinstance(path_c, list)
                            and len(path_c) + len(rhs_p) > _MAX_TRACKED_LIST_LEN
                        ) or (
                            rhs_f is not None
                            and isinstance(fn_c, list)
                            and len(fn_c) + len(rhs_f) > _MAX_TRACKED_LIST_LEN
                        ):
                            _untrack_mutable_container(node.target.value)
                            return None
                        if rhs_p is not None and isinstance(path_c, list):
                            new_p = list(path_c[slice_obj]) + rhs_p
                            if (
                                _assign_list_slice(path_c, slice_obj, new_p)
                                and cmd_name is not None
                            ):
                                if all(isinstance(x, str) for x in rhs_p) and _assign_list_slice(
                                    cmd_list_vars[cmd_name],
                                    slice_obj,
                                    list(cmd_list_vars[cmd_name][slice_obj]) + rhs_p,
                                ):
                                    pass
                                else:
                                    cmd_list_vars.pop(cmd_name, None)
                        if rhs_f is not None and isinstance(fn_c, list):
                            new_f = list(fn_c[slice_obj]) + rhs_f
                            _assign_list_slice(fn_c, slice_obj, new_f)
                elif isinstance(node.target, ast.Name) and node.target.id in path_vars:
                    rhs_path = _resolve_path_node(node.value)
                    _flush_unapplied_expr_calls(node.value)
                    if (
                        isinstance(rhs_path, str)
                        and len(path_vars[node.target.id]) + len(rhs_path) <= _MAX_TRACKED_STR_LEN
                    ):
                        path_vars[node.target.id] = path_vars[node.target.id] + rhs_path
                    else:
                        path_vars.pop(node.target.id, None)
                else:
                    handled_str_slot = False
                    if isinstance(node.target, ast.Subscript):
                        base_aug, slices_aug = _unwrap_subscripts(node.target)
                        parent_path_aug: Any = None
                        cmd_name_aug: str | None = None
                        if slices_aug:
                            if isinstance(base_aug, ast.Name):
                                var_name_aug = base_aug.id
                                base_path_aug: Any = (
                                    list_path_vars[var_name_aug]
                                    if var_name_aug in list_path_vars
                                    else dict_path_vars.get(var_name_aug)
                                )
                                parent_path_aug = _walk_container_slices(
                                    base_path_aug, slices_aug[:-1]
                                )
                                if len(slices_aug) == 1 and var_name_aug in cmd_list_vars:
                                    cmd_name_aug = var_name_aug
                            elif _is_setdefault_call(base_aug):
                                base_path_aug, _, _ = _resolve_mutable_containers(
                                    base_aug, create_list=True, create_dict=True
                                )
                                parent_path_aug = _walk_container_slices(
                                    base_path_aug, slices_aug[:-1]
                                )
                        if isinstance(parent_path_aug, dict):
                            last_k_aug = _extract_path_str(slices_aug[-1])
                            if (
                                last_k_aug is not None
                                and last_k_aug in parent_path_aug
                                and isinstance(parent_path_aug[last_k_aug], str)
                            ):
                                handled_str_slot = True
                                rhs_path = _resolve_path_node(node.value)
                                _flush_unapplied_expr_calls(node.value)
                                if (
                                    isinstance(rhs_path, str)
                                    and len(parent_path_aug[last_k_aug]) + len(rhs_path)
                                    <= _MAX_TRACKED_STR_LEN
                                ):
                                    parent_path_aug[last_k_aug] = (
                                        parent_path_aug[last_k_aug] + rhs_path
                                    )
                                else:
                                    parent_path_aug[last_k_aug] = _NON_STR_VAL
                        elif isinstance(parent_path_aug, list):
                            idx_aug = _extract_int_node(slices_aug[-1])
                            if (
                                idx_aug is not None
                                and -len(parent_path_aug) <= idx_aug < len(parent_path_aug)
                                and isinstance(parent_path_aug[idx_aug], str)
                            ):
                                handled_str_slot = True
                                rhs_path = _resolve_path_node(node.value)
                                _flush_unapplied_expr_calls(node.value)
                                if (
                                    isinstance(rhs_path, str)
                                    and len(parent_path_aug[idx_aug]) + len(rhs_path)
                                    <= _MAX_TRACKED_STR_LEN
                                ):
                                    new_slot_str = parent_path_aug[idx_aug] + rhs_path
                                    parent_path_aug[idx_aug] = new_slot_str
                                    if (
                                        cmd_name_aug is not None
                                        and cmd_name_aug in cmd_list_vars
                                        and -len(cmd_list_vars[cmd_name_aug])
                                        <= idx_aug
                                        < len(cmd_list_vars[cmd_name_aug])
                                    ):
                                        cmd_list_vars[cmd_name_aug][idx_aug] = new_slot_str
                                else:
                                    parent_path_aug[idx_aug] = None
                                    if cmd_name_aug is not None:
                                        cmd_list_vars.pop(cmd_name_aug, None)
                    if not handled_str_slot:
                        rhs_path = _resolve_path_node(node.value)
                        rhs_fn = _resolve_fn_container(node.value)
                        _flush_unapplied_expr_calls(node.value)
                        rhs_p, rhs_f = _slice_rhs_lists(rhs_path, rhs_fn)
                        path_c, fn_c, cmd_name = _resolve_mutable_containers(
                            node.target,
                            create_list=(
                                isinstance(rhs_path, list) or isinstance(rhs_fn, list)
                            ),
                        )
                        if (
                            (rhs_p is None and rhs_f is None)
                            or (
                                rhs_p is not None
                                and isinstance(path_c, list)
                                and len(path_c) + len(rhs_p) > _MAX_TRACKED_LIST_LEN
                            )
                            or (
                                rhs_f is not None
                                and isinstance(fn_c, list)
                                and len(fn_c) + len(rhs_f) > _MAX_TRACKED_LIST_LEN
                            )
                        ):
                            _untrack_mutable_container(node.target)
                        else:
                            if rhs_p is not None and isinstance(path_c, list):
                                path_c.extend(rhs_p)
                                if cmd_name is not None:
                                    if all(isinstance(x, str) for x in rhs_p):
                                        cmd_list_vars[cmd_name].extend(rhs_p)
                                    else:
                                        cmd_list_vars.pop(cmd_name, None)
                            if rhs_f is not None and isinstance(fn_c, list):
                                fn_c.extend(rhs_f)
        elif isinstance(node, ast.Call):
            kind = _resolve_callable_kind(node.func)
            if kind is None and isinstance(node.func, ast.Attribute):
                _apply_mutating_call(node)
            elif kind == "rmtree":
                pos_candidates: list[str | None] = []
                for arg in node.args:
                    if isinstance(arg, ast.Starred):
                        unpacked = (
                            _resolve_iterable_path_only(arg.value)
                            if _is_reversed_call(arg.value)
                            else _resolve_path_node(arg.value)
                        )
                        _flush_unapplied_expr_calls(arg.value)
                        if isinstance(unpacked, list):
                            for item in unpacked:
                                pos_candidates.append(item if isinstance(item, str) else None)
                        elif isinstance(unpacked, Mapping):
                            for item_k in unpacked:
                                pos_candidates.append(str(item_k))
                    else:
                        pos_candidates.append(_extract_path_str(arg))
                        _flush_unapplied_expr_calls(arg)
                target_str: str | None = pos_candidates[0] if pos_candidates else None
                for kw in node.keywords:
                    if target_str is None:
                        if kw.arg == "path":
                            target_str = _extract_path_str(kw.value)
                        elif kw.arg is None:
                            kw_val = _resolve_path_node(kw.value)
                            if isinstance(kw_val, Mapping):
                                p_val = kw_val.get("path")
                                if isinstance(p_val, str):
                                    target_str = p_val
                                else:
                                    d_val = kw_val.get("dir_fd")
                                    if isinstance(d_val, str):
                                        target_str = d_val
                    _flush_unapplied_expr_calls(kw.value)
                if target_str is not None and _is_critical_rm_target(target_str):
                    return "safety_floor:destructive_rm_root_or_glob"
            elif kind in {"subprocess_cmd", "os_cmd"}:
                cmd_node: ast.AST | None = None
                starred_cmd_val: Any = None
                if node.args:
                    if isinstance(node.args[0], ast.Starred):
                        unpacked = (
                            _resolve_iterable_path_only(node.args[0].value)
                            if _is_reversed_call(node.args[0].value)
                            else _resolve_path_node(node.args[0].value)
                        )
                        if isinstance(unpacked, list) and unpacked:
                            starred_cmd_val = unpacked[0]
                    else:
                        cmd_node = node.args[0]
                if cmd_node is None and starred_cmd_val is None:
                    kw_names = ("args",) if kind == "subprocess_cmd" else ("cmd", "command")
                    for kw in node.keywords:
                        if kw.arg in kw_names:
                            cmd_node = kw.value
                            break
                        if kw.arg is None:
                            kw_val = _resolve_path_node(kw.value)
                            if isinstance(kw_val, Mapping):
                                for k_name in kw_names:
                                    if k_name in kw_val:
                                        starred_cmd_val = kw_val[k_name]
                                        break
                                if starred_cmd_val is not None:
                                    break
                cmd_list: list[str] | None = None
                cmd_str: str | None = None
                if cmd_node is not None:
                    cmd_list = _extract_cmd_lst(cmd_node)
                    if not cmd_list:
                        cmd_str = _extract_path_str(cmd_node)
                elif starred_cmd_val is not None:
                    if isinstance(starred_cmd_val, list) and all(
                        isinstance(x, str) for x in starred_cmd_val
                    ):
                        cmd_list = list(starred_cmd_val)
                    elif isinstance(starred_cmd_val, str):
                        cmd_str = starred_cmd_val
                for arg in node.args:
                    _flush_unapplied_expr_calls(arg.value if isinstance(arg, ast.Starred) else arg)
                for kw in node.keywords:
                    _flush_unapplied_expr_calls(kw.value)
                if cmd_list:
                    raw_head = Path(cmd_list[0].strip("\"'")).name.lower()
                    eff_cmd_list = (
                        _unwrap_command_tokens(cmd_list)
                        if raw_head in _WRAPPER_COMMANDS
                        else cmd_list
                    )
                    cmd_head = (
                        Path(eff_cmd_list[0].strip("\"'")).name.lower() if eff_cmd_list else ""
                    )
                    is_python_cmd = _is_python_cmd_name(cmd_head)
                    script_idx: int | None = None
                    inline_script: str | None = None
                    if is_python_cmd:
                        script_idx, inline_script = _find_python_c_script(eff_cmd_list)
                    elif (
                        len(eff_cmd_list) >= 3
                        and cmd_head in {"sh", "bash", "dash", "zsh", "ksh"}
                    ):
                        script_idx = _find_sh_c_script_index(eff_cmd_list, is_python=False)
                    reconstructed = shlex.join(cmd_list)
                    if not (
                        _ast_depth < 4
                        and _is_python_cmd_name(raw_head)
                        and script_idx is not None
                    ):
                        sub_trunc_cmd = [False]
                        violation = _check_deobfuscated_commands(
                            reconstructed,
                            _cmd_depth=_cmd_depth,
                            _ast_depth=_ast_depth,
                            _step_budget=_step_budget,
                            _ast_step_budget=_ast_step_budget,
                            _char_budget=_char_budget,
                            _seen_texts=_seen_texts,
                            _truncated_out=sub_trunc_cmd,
                        )
                        if sub_trunc_cmd[0]:
                            truncated_by_depth = True
                        if violation is not None:
                            return violation
                    pattern_violation = _match_safety_patterns(reconstructed)
                    if pattern_violation is not None:
                        return pattern_violation
                    if _ast_depth < 4 and script_idx is not None:
                        script_text = (
                            inline_script
                            if inline_script is not None
                            else eff_cmd_list[script_idx]
                        )
                        sub_trunc = [False]
                        sub_violation = _check_text_against_safety_patterns(
                            script_text,
                            _ast_depth=_ast_depth + 1,
                            _cmd_depth=_cmd_depth,
                            _step_budget=_step_budget,
                            _ast_step_budget=_ast_step_budget,
                            _char_budget=_char_budget,
                            _seen_texts=_seen_texts,
                            _truncated_out=sub_trunc,
                        )
                        if sub_trunc[0]:
                            truncated_by_depth = True
                        if sub_violation is not None:
                            return sub_violation
                    elif _ast_depth >= 4 and script_idx is not None:
                        truncated_by_depth = True
                        if is_python_cmd:
                            if _truncated_out is not None:
                                _truncated_out[0] = True
                            return "safety_floor:python_ast_complexity_budget_exceeded"
                elif cmd_str is not None and cmd_str.strip():
                    if _ast_depth < 4:
                        sub_trunc_str = [False]
                        violation = _check_text_against_safety_patterns(
                            cmd_str,
                            _ast_depth=_ast_depth + 1,
                            _cmd_depth=_cmd_depth,
                            _step_budget=_step_budget,
                            _ast_step_budget=_ast_step_budget,
                            _char_budget=_char_budget,
                            _seen_texts=_seen_texts,
                            _truncated_out=sub_trunc_str,
                        )
                        if sub_trunc_str[0]:
                            truncated_by_depth = True
                    else:
                        truncated_by_depth = True
                        sub_trunc_str = [False]
                        violation = _check_deobfuscated_commands(
                            cmd_str,
                            _cmd_depth=_cmd_depth,
                            _ast_depth=_ast_depth,
                            _step_budget=_step_budget,
                            _ast_step_budget=_ast_step_budget,
                            _char_budget=_char_budget,
                            _seen_texts=_seen_texts,
                            _truncated_out=sub_trunc_str,
                        )
                        if sub_trunc_str[0]:
                            truncated_by_depth = True
                    if violation is not None:
                        return violation
        return None

    _MAX_AST_VISITED_NODES = 20_000
    stack: list[ast.AST] = [tree]
    while stack:
        _ast_step_budget[0] += 1
        if _ast_step_budget[0] > _MAX_AST_VISITED_NODES:
            return "safety_floor:python_ast_complexity_budget_exceeded", is_python_module
        cur_node = stack.pop()
        res = _visit_node(cur_node)
        if res is not None:
            if _truncated_out is not None and truncated_by_depth:
                _truncated_out[0] = True
            return res, is_python_module
        children = list(ast.iter_child_nodes(cur_node))
        for child in reversed(children):
            stack.append(child)
    if _truncated_out is not None and truncated_by_depth:
        _truncated_out[0] = True
    return None, is_python_module


def _check_python_ast_calls(
    text: str,
    *,
    _ast_depth: int = 0,
    _ast_step_budget: list[int] | None = None,
    _step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
    _cmd_depth: int = 0,
) -> str | None:
    res, _ = _check_python_ast_calls_impl(
        text,
        _ast_depth=_ast_depth,
        _ast_step_budget=_ast_step_budget,
        _step_budget=_step_budget,
        _char_budget=_char_budget,
        _cmd_depth=_cmd_depth,
    )
    return res


def _check_python_shutil_rmtree(text: str) -> str | None:
    return _check_python_ast_calls(text)


def _wrapper_short_cluster_takes_arg(tok: str, arg_opts: frozenset[str]) -> bool:
    if tok in arg_opts:
        return True
    if len(tok) > 2 and tok.startswith("-") and not tok.startswith("--"):
        # In POSIX getopt, if any earlier flag in the cluster consumes an argument,
        # the trailing characters belong to that option's argument, not a new option.
        for ch in tok[1:-1]:
            if f"-{ch}" in arg_opts:
                return False
        return f"-{tok[-1]}" in arg_opts
    return False


_XARGS_ARG_OPTIONS: frozenset[str] = frozenset(
    {"-I", "-J", "-L", "-n", "-P", "-s", "-E", "-d", "-a"}
)
_XARGS_LONG_ARG_OPTIONS: frozenset[str] = frozenset(
    {
        "--max-args",
        "--max-procs",
        "--max-chars",
        "--delimiter",
        "--arg-file",
        "--process-slot-var",
    }
)


def _consume_leading_redirection(tokens: list[str]) -> bool:
    if not tokens:
        return False
    tok = tokens[0]
    m = _SHELL_REDIR_OP_RE.match(tok)
    if m is None:
        return False
    while m is not None:
        pos = m.end()
        if pos == len(tok):
            tokens.pop(0)
            if tokens:
                tokens.pop(0)
            return True
        j = pos
        while j < len(tok) and tok[j] not in "<>":
            j += 1
        if j >= len(tok):
            tokens.pop(0)
            return True
        m = _SHELL_REDIR_OP_RE.match(tok, j)
    tokens.pop(0)
    return True


def _split_env_string_tokens(split_str: str) -> list[str]:
    if not split_str.strip():
        return []
    try:
        return _posix_shlex_split(split_str)
    except ValueError:
        return split_str.split()


def _shell_cmd_name(token: str) -> str:
    cleaned = token.strip("\"'")
    if "/" in cleaned:
        cleaned = posixpath.basename(cleaned.rstrip("/"))
    return cleaned.lower()


def _unwrap_command_tokens(raw_tokens: list[str]) -> list[str]:
    tokens = list(raw_tokens)
    while tokens:
        if "=" in tokens[0] and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens.pop(0)
            continue
        if _consume_leading_redirection(tokens):
            continue
        break
    env_split_count = 0
    while tokens and _shell_cmd_name(tokens[0]) in _WRAPPER_COMMANDS:
        wrapper = _shell_cmd_name(tokens.pop(0))
        arg_opts = _WRAPPER_ARG_OPTIONS.get(wrapper, frozenset())
        while tokens:
            tok = tokens[0]
            if tok == "--":
                tokens.pop(0)
                break
            if _consume_leading_redirection(tokens):
                continue
            if tok.startswith("-"):
                tokens.pop(0)
                if wrapper == "env" and env_split_count < 8:
                    split_str: str | None = None
                    if tok == "--split-string":
                        if tokens:
                            split_str = tokens.pop(0)
                    elif tok.startswith("--split-string="):
                        split_str = tok.split("=", 1)[1]
                    elif not tok.startswith("--") and len(tok) >= 2:
                        for idx_c, ch in enumerate(tok[1:], start=1):
                            opt = f"-{ch}"
                            if opt in arg_opts:
                                if ch == "S":
                                    if idx_c + 1 < len(tok):
                                        split_str = tok[idx_c + 1 :]
                                    elif tokens:
                                        split_str = tokens.pop(0)
                                elif idx_c + 1 == len(tok) and tokens:
                                    tokens.pop(0)
                                break
                    elif _wrapper_short_cluster_takes_arg(tok, arg_opts) and tokens:
                        tokens.pop(0)
                    if split_str is not None:
                        env_split_count += 1
                        split_tokens = _split_env_string_tokens(split_str)
                        if split_tokens:
                            tokens = split_tokens + tokens
                    continue
                if _wrapper_short_cluster_takes_arg(tok, arg_opts) and tokens:
                    tokens.pop(0)
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tok):
                tokens.pop(0)
                continue
            break
        while _consume_leading_redirection(tokens):
            pass
        if wrapper == "timeout" and tokens and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tokens[0]):
            tokens.pop(0)
        while _consume_leading_redirection(tokens):
            pass
    return tokens


def _parse_rm_tokens(args: list[str]) -> tuple[bool, bool, list[str]]:
    after_dashdash = False
    has_recursive = False
    has_force = False
    targets: list[str] = []
    for tok in args:
        if not after_dashdash and tok == "--":
            after_dashdash = True
            continue
        if not after_dashdash and tok.startswith("--"):
            low_tok = tok.lower()
            if low_tok == "--recursive":
                has_recursive = True
            elif low_tok == "--force":
                has_force = True
            continue
        if not after_dashdash and tok.startswith("-") and len(tok) > 1:
            flags = tok[1:].lower()
            if "r" in flags:
                has_recursive = True
            if "f" in flags:
                has_force = True
            continue
        targets.append(tok.strip("\"'"))
    return has_recursive, has_force, targets


def _check_rm_targets(has_recursive: bool, has_force: bool, targets: list[str]) -> str | None:
    for target in targets:
        low_target = target.lower()
        if (
            low_target == ".git"
            or "/.git" in low_target
            or ".git/" in low_target
            or low_target.endswith((".sqlite", ".sqlite3", ".db"))
        ):
            return "safety_floor:destructive_db_or_git_wipe"
        if (has_recursive or has_force) and _is_critical_rm_target(target):
            return "safety_floor:destructive_rm_root_or_glob"
    return None


def _consume_redirection_at(tokens: list[str], idx: int) -> int | None:
    if idx >= len(tokens):
        return None
    tok = tokens[idx]
    m = _SHELL_REDIR_OP_RE.match(tok)
    if m is None:
        return None
    pos = m.end()
    if pos == len(tok):
        return min(len(tokens), idx + 2)
    j = pos
    while j < len(tok) and tok[j] not in "<>":
        j += 1
    while j < len(tok):
        m2 = _SHELL_REDIR_OP_RE.match(tok, j)
        if m2 is None:
            break
        pos2 = m2.end()
        if pos2 == len(tok):
            return min(len(tokens), idx + 2)
        j = pos2
        while j < len(tok) and tok[j] not in "<>":
            j += 1
    return idx + 1


def _extract_find_starting_paths(tokens: list[str]) -> tuple[list[str], int]:
    idx = 1
    while idx < len(tokens):
        nxt_idx = _consume_redirection_at(tokens, idx)
        if nxt_idx is not None:
            idx = nxt_idx
            continue
        if tokens[idx] in {"-H", "-L", "-P"} or re.fullmatch(r"-O\d+", tokens[idx]) is not None:
            idx += 1
            continue
        break
    starting_paths: list[str] = []
    while idx < len(tokens):
        nxt_idx = _consume_redirection_at(tokens, idx)
        if nxt_idx is not None:
            idx = nxt_idx
            continue
        tok = tokens[idx]
        if tok.startswith("-") or tok in {"(", "!", ",", r"\,"}:
            break
        starting_paths.append(tok.strip("\"'"))
        idx += 1
    return starting_paths, idx


def _extract_xargs_inner_and_replace(args: list[str]) -> tuple[list[str], str | None]:
    idx = 0
    replace_str: str | None = None
    while idx < len(args):
        nxt_idx = _consume_redirection_at(args, idx)
        if nxt_idx is not None:
            idx = nxt_idx
            continue
        tok = args[idx]
        if tok == "--":
            idx += 1
            break
        if not tok.startswith("-") or tok == "-":
            break
        if tok.startswith("--"):
            idx += 1
            if tok.startswith("--replace="):
                replace_str = tok.split("=", 1)[1] or "{}"
            elif tok == "--replace":
                replace_str = "{}"
            elif "=" not in tok and tok in _XARGS_LONG_ARG_OPTIONS and idx < len(args):
                idx += 1
            continue
        idx += 1
        for pos, ch in enumerate(tok[1:], start=1):
            opt = f"-{ch}"
            if opt in _XARGS_ARG_OPTIONS:
                if pos + 1 < len(tok):
                    if ch == "I":
                        replace_str = tok[pos + 1 :]
                elif idx < len(args):
                    if ch == "I":
                        replace_str = args[idx]
                    idx += 1
                break
            if ch == "i":
                if pos + 1 < len(tok):
                    replace_str = tok[pos + 1 :] or "{}"
                    break
                replace_str = "{}"
            elif ch in {"e", "l"} and pos + 1 < len(tok):
                break
    return args[idx:], replace_str


def _extract_xargs_inner_tokens(args: list[str]) -> list[str]:
    inner, _ = _extract_xargs_inner_and_replace(args)
    return inner


_DQUOTE_END_OR_ESC_RE = re.compile(r'[\\"]')
_GROUP_SCAN_RE = re.compile(r"""[\\'"#(){}]""")


def _find_closing_double_quote(text: str, start: int, end: int | None = None) -> int:
    n = len(text) if end is None else end
    idx = start
    while idx < n:
        m = _DQUOTE_END_OR_ESC_RE.search(text, idx, n)
        if m is None:
            return -1
        pos = m.start()
        if text[pos] == '"':
            return pos
        idx = pos + 2
    return -1


def _has_closing_double_quote(text: str, start: int, end: int | None = None) -> bool:
    return _find_closing_double_quote(text, start, end) != -1


def _match_shell_groups(text: str) -> tuple[dict[int, int], set[int]]:
    pairs: dict[int, int] = {}
    closers: set[int] = set()
    stack: list[tuple[str, int]] = []
    i = 0
    n = len(text)
    while i < n:
        m = _GROUP_SCAN_RE.search(text, i)
        if m is None:
            break
        i = m.start()
        ch = text[i]
        if ch == "\\":
            i += 2 if i + 1 < n else 1
            continue
        if ch == "'":
            close_sq = text.find("'", i + 1)
            i = close_sq + 1 if close_sq != -1 else i + 1
            continue
        if ch == '"':
            close_dq = _find_closing_double_quote(text, i + 1)
            i = close_dq + 1 if close_dq != -1 else i + 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            nl = text.find("\n", i + 1)
            cr = text.find("\r", i + 1)
            if nl == -1:
                i = cr if cr != -1 else n
            elif cr == -1:
                i = nl
            else:
                i = nl if nl < cr else cr
            continue
        if ch == "(":
            stack.append(("(", i))
        elif ch == ")":
            if stack and stack[-1][0] == "(":
                _, open_idx = stack.pop()
                pairs[open_idx] = i
                closers.add(i)
        elif ch == "{":
            if (
                (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&({!")
                and i + 1 < n
                and (text[i + 1].isspace() or text[i + 1] == ";")
            ):
                stack.append(("{", i))
        elif (
            ch == "}"
            and stack
            and stack[-1][0] == "{"
            and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&)}")
            and (i + 1 == n or text[i + 1].isspace() or text[i + 1] in ";|&)}<>")
        ):
            _, open_idx = stack.pop()
            pairs[open_idx] = i
            closers.add(i)
        i += 1
    return pairs, closers


_SHELL_REDIR_OP_RE = re.compile(
    r"&>>|&>|(?:\{[A-Za-z_][A-Za-z0-9_]*\}|\d*)(?:<<-|<<<|<<|>>|<&|>&|<>|>\||<|>)"
)


def _is_shell_redirection_tail(tail: str) -> bool:
    i = 0
    n = len(tail)
    while i < n:
        while i < n:
            if tail[i].isspace():
                i += 1
                continue
            if tail.startswith("\\\r\n", i):
                i += 3
                continue
            if tail.startswith("\\\n", i):
                i += 2
                continue
            break
        if i >= n:
            return True
        if i == n - 1 and tail[i] == "\\":
            return True
        m = _SHELL_REDIR_OP_RE.match(tail, i)
        if m is None:
            return False
        i = m.end()
        while i < n and tail[i] in " \t":
            i += 1
        if i >= n:
            return False
        word_start = i
        in_single = False
        in_double = False
        while i < n:
            ch = tail[i]
            if in_single:
                if ch == "'":
                    in_single = False
                i += 1
                continue
            if in_double:
                if ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == '"':
                    in_double = False
                i += 1
                continue
            if ch == "\\":
                if i + 1 >= n:
                    break
                i += 2
                continue
            if ch == "'":
                in_single = True
                i += 1
                continue
            if ch == '"':
                in_double = True
                i += 1
                continue
            if ch.isspace():
                break
            if ch in "<>":
                break
            if ch in ";|&()":
                return False
            i += 1
        if in_single or in_double or i == word_start:
            return False
    return True


def _unwrap_matching_groups(text: str) -> str | None:
    s = text.strip()
    if len(s) < 2 or s[0] not in {"(", "{"}:
        return None
    pairs, _ = _match_shell_groups(s)
    start = 0
    end = len(s)
    unwrapped_any = False
    while True:
        while start < end and s[start].isspace():
            start += 1
        while end > start and s[end - 1].isspace():
            end -= 1
        if end - start < 2 or s[start] not in {"(", "{"}:
            break
        close_idx = pairs.get(start)
        if close_idx is None or close_idx >= end:
            break
        if close_idx == end - 1:
            start += 1
            end -= 1
            unwrapped_any = True
            continue
        if _is_shell_redirection_tail(s[close_idx + 1 : end]):
            start += 1
            end = close_idx
            unwrapped_any = True
            continue
        break
    if not unwrapped_any:
        return None
    return s[start:end].strip()


def _split_shell_outside_quotes(
    text: str, seps: tuple[str, ...], *, respect_groups: bool = False
) -> list[str]:
    ordered_seps = tuple(sorted(seps, key=len, reverse=True))
    pairs, closers = _match_shell_groups(text) if respect_groups else ({}, set())
    group_depth = 0
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    prev_was_escaped = False
    pending_op_continuation = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            prev_was_escaped = False
            pending_op_continuation = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(text[i + 1])
                prev_was_escaped = False
                pending_op_continuation = False
                i += 2
                continue
            buf.append(ch)
            if ch == '"':
                in_double = False
            prev_was_escaped = False
            pending_op_continuation = False
            i += 1
            continue
        if ch == "\\":
            buf.append(ch)
            if i + 1 < n:
                nxt_ch = text[i + 1]
                buf.append(nxt_ch)
                prev_was_escaped = nxt_ch not in {"\n", "\r"}
                if nxt_ch not in {"\n", "\r"}:
                    pending_op_continuation = False
                i += 2
            else:
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
            continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            buf.append(ch)
            prev_was_escaped = False
            pending_op_continuation = False
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            buf.append(ch)
            prev_was_escaped = False
            pending_op_continuation = False
            i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            while i < n and text[i] not in {"\n", "\r"}:
                i += 1
            prev_was_escaped = False
            continue
        if respect_groups:
            if i in pairs:
                group_depth += 1
                buf.append(ch)
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
                continue
            if i in closers:
                group_depth = max(0, group_depth - 1)
                buf.append(ch)
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
                continue
        if not respect_groups or group_depth == 0:
            if "|" in ordered_seps and "||" not in ordered_seps and text.startswith("||", i):
                buf.append("||")
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "&" in ordered_seps and "|&" not in ordered_seps and text.startswith("|&", i):
                buf.append("|&")
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "&&" not in ordered_seps and text.startswith("&&", i):
                buf.append("&&")
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "||" not in ordered_seps and text.startswith("||", i):
                buf.append("||")
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            matched_sep: str | None = None
            for sep in ordered_seps:
                if text.startswith(sep, i):
                    if sep == "|" and i > 0 and text[i - 1] == ">" and not prev_was_escaped:
                        continue
                    if sep == "&" and (
                        (i > 0 and text[i - 1] in {">", "<", "|"} and not prev_was_escaped)
                        or text.startswith("&>", i)
                    ):
                        continue
                    matched_sep = sep
                    break
            if matched_sep is not None:
                if matched_sep in {"\n", "\r\n"} and pending_op_continuation:
                    buf.append(matched_sep)
                    prev_was_escaped = False
                    i += len(matched_sep)
                    continue
                parts.append("".join(buf))
                buf.clear()
                prev_was_escaped = False
                pending_op_continuation = False
                i += len(matched_sep)
                continue
        buf.append(ch)
        if ch in {" ", "\t"}:
            pass
        elif ch == "|" and not (i > 0 and text[i - 1] == ">" and not prev_was_escaped):
            pending_op_continuation = True
        else:
            pending_op_continuation = False
        prev_was_escaped = False
        i += 1
    parts.append("".join(buf))
    return parts


_MAX_SHELL_EXPANDED_CHARS: int = 1_500_000


class _ShellComplexityBudgetExceeded(Exception):
    pass


def _bounded_str_replace(
    text: str,
    old: str,
    new: str,
    char_budget: list[int],
) -> str:
    if not old or old not in text:
        return text
    new_len = len(new)
    if new_len > len(old):
        count = text.count(old)
        char_budget[0] += count * (new_len - len(old))
        if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
            raise _ShellComplexityBudgetExceeded()
    return text.replace(old, new)


_SHELL_NUMERIC_PARAM_RE = re.compile(
    r'"\$\{(\d+)(?:(:?[-+?])([^}]*))?\}"'
    r'|"\$(\d+)"'
    r'|\$\{(\d+)(?:(:?[-+?])([^}]*))?\}'
    r'|\$(\d+)(?![A-Za-z0-9_])'
)
_SHELL_PARAM_AT_RAW_RE = re.compile(r"\$\{?@\}?")
_SHELL_PARAM_STAR_RAW_RE = re.compile(r"\$\{?\*\}?")
_SHELL_PARAM_AT_STAR_RE = re.compile(
    r'("\$\{?@\}?")|(\$\{?@\}?)|("\$\{?\*\}?")|(\$\{?\*\}?)'
)
_SHELL_VAR_REF_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])"
)
_PYTHON_CMD_NAME_RE = re.compile(r"python(?:\d+(?:\.\d+)?)?")
_PYTHON_ARG_OPTIONS: frozenset[str] = frozenset({"W", "X", "Q"})
_PYTHON_LONG_ARG_OPTIONS: frozenset[str] = frozenset({"--check-hash-based-pycs"})


def _is_python_cmd_name(cmd_head: str) -> bool:
    return _PYTHON_CMD_NAME_RE.fullmatch(cmd_head) is not None


def _replace_shell_positional_params(
    script: str,
    pos_args: Sequence[str],
    *,
    _char_budget: list[int] | None = None,
) -> str:
    if "$" not in script:
        return script
    char_budget = _char_budget if _char_budget is not None else [0]

    def _charge(rep: str, match_len: int) -> str:
        rep_len = len(rep)
        if rep_len > match_len:
            char_budget[0] += rep_len - match_len
        elif rep_len > 0:
            char_budget[0] += rep_len
        if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
            raise _ShellComplexityBudgetExceeded()
        return rep

    def _repl(m: re.Match[str]) -> str:
        if m.group(1) is not None:
            idx = int(m.group(1))
            op = m.group(2)
            operand = m.group(3)
            is_quoted = True
        elif m.group(4) is not None:
            idx = int(m.group(4))
            op = None
            operand = None
            is_quoted = True
        elif m.group(5) is not None:
            idx = int(m.group(5))
            op = m.group(6)
            operand = m.group(7)
            is_quoted = False
        else:
            idx = int(m.group(8))
            op = None
            operand = None
            is_quoted = False

        match_len = m.end() - m.start()
        is_set = idx < len(pos_args)
        val = pos_args[idx] if is_set else ""
        if op is None:
            if not is_set:
                return m.group(0)
            rep = shlex.quote(val) if is_quoted else val
            return _charge(rep, match_len)
        if op in {":-", "-"}:
            use_default = (not is_set) or (op == ":-" and val == "")
            chosen = (operand or "") if use_default else val
            rep = shlex.quote(chosen) if is_quoted else chosen
            return _charge(rep, match_len)
        if op in {":+", "+"}:
            use_alt = is_set and (op != ":+" or val != "")
            chosen = (operand or "") if use_alt else ""
            if not chosen and is_quoted:
                return _charge("''", match_len)
            rep = shlex.quote(chosen) if is_quoted else chosen
            return _charge(rep, match_len)
        # op in {":?", "?"}
        if not is_set or (op == ":?" and val == ""):
            return m.group(0)
        rep = shlex.quote(val) if is_quoted else val
        return _charge(rep, match_len)

    return _SHELL_NUMERIC_PARAM_RE.sub(_repl, script)


def _replace_shell_at_star_params(
    script: str,
    *,
    at_val: str | None = None,
    star_val: str | None = None,
    quote_at: bool = False,
    _char_budget: list[int] | None = None,
) -> str:
    if "$" not in script:
        return script
    has_at = at_val is not None and "@" in script
    has_star = star_val is not None and "*" in script
    if not has_at and not has_star:
        return script
    char_budget = _char_budget if _char_budget is not None else [0]
    quoted_at = (shlex.quote(at_val) if quote_at else at_val) if at_val is not None else None
    quoted_star = shlex.quote(star_val) if star_val is not None else None

    def _repl(m: re.Match[str]) -> str:
        if m.group(1) is not None:
            if quoted_at is None:
                return m.group(0)
            rep = quoted_at
        elif m.group(2) is not None:
            if at_val is None:
                return m.group(0)
            rep = at_val
        elif m.group(3) is not None:
            if quoted_star is None:
                return m.group(0)
            rep = quoted_star
        else:
            if star_val is None:
                return m.group(0)
            rep = star_val
        char_budget[0] += max(1, len(rep))
        if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
            raise _ShellComplexityBudgetExceeded()
        return rep

    return _SHELL_PARAM_AT_STAR_RE.sub(_repl, script)


def _find_python_c_script(tokens: list[str]) -> tuple[int | None, str | None]:
    if len(tokens) < 2:
        return None, None
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in {"--", "-"}:
            return None, None
        if tok.startswith("--"):
            idx += 1
            if "=" not in tok and tok in _PYTHON_LONG_ARG_OPTIONS:
                if idx >= len(tokens):
                    return None, None
                idx += 1
            continue
        if not tok.startswith("-"):
            return None, None
        consumed_arg = False
        for pos in range(1, len(tok)):
            ch = tok[pos]
            if ch == "c":
                if pos + 1 < len(tok):
                    return idx, tok[pos + 1 :]
                script_idx = idx + 1
                return (script_idx, None) if script_idx < len(tokens) else (None, None)
            if ch == "m":
                return None, None
            if ch in _PYTHON_ARG_OPTIONS:
                if pos + 1 < len(tok):
                    idx += 1
                else:
                    idx += 2
                consumed_arg = True
                break
            if not (ch.isalpha() or ch == "?"):
                return None, None
        if not consumed_arg:
            idx += 1
    return None, None


def _find_sh_c_script_index(tokens: list[str], *, is_python: bool = False) -> int | None:
    if is_python:
        script_idx, _ = _find_python_c_script(tokens)
        return script_idx
    if len(tokens) < 3:
        return None
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            return None
        if tok.startswith("--"):
            idx += 1
            if "=" not in tok and tok in {"--rcfile", "--init-file"} and idx < len(tokens):
                idx += 1
            continue
        if not tok.startswith(("-", "+")) or len(tok) < 2:
            return None
        if tok == "-c" or (
            tok.startswith("-") and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", tok) is not None
        ):
            script_idx = idx + (2 if tok[-1] in {"o", "O"} else 1)
            if script_idx < len(tokens) and tokens[script_idx] == "--":
                script_idx += 1
            return script_idx if script_idx < len(tokens) else None
        if tok in {"-o", "-O", "+o", "+O"} or re.fullmatch(r"[+-][A-Za-z]+[oO]", tok) is not None:
            idx += 2
            continue
        if re.fullmatch(r"[+-][A-Za-z]+", tok) is not None:
            idx += 1
            continue
        return None
    return None


def _expand_loop_var_tokens(
    tokens: list[str],
    loop_vars: Mapping[str, list[str]],
    *,
    _step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
) -> list[list[str]]:
    if not loop_vars or not any("$" in tok for tok in tokens):
        return [tokens]
    referenced_set: set[str] = set()
    dollar_indices: list[int] = []
    for idx, tok in enumerate(tokens):
        if "$" not in tok:
            continue
        dollar_indices.append(idx)
        for m in _SHELL_VAR_REF_RE.finditer(tok):
            var_name = m.group(1) or m.group(2)
            if var_name in loop_vars and loop_vars[var_name]:
                referenced_set.add(var_name)
    if not referenced_set:
        return [tokens]
    referenced = [var for var in loop_vars if var in referenced_set]
    single_vals: dict[str, str] = {}
    multi_vars: list[str] = []
    for var in referenced:
        vals = loop_vars[var]
        if len(vals) == 1:
            single_vals[var] = vals[0]
        else:
            multi_vars.append(var)
    if _step_budget is not None:
        _step_budget[0] += len(dollar_indices)
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            return [tokens]
    char_budget = _char_budget if _char_budget is not None else [0]
    base_tokens = list(tokens)
    if single_vals:
        def _sub_single(m: re.Match[str]) -> str:
            vn = m.group(1) or m.group(2)
            if vn in single_vals:
                rep = single_vals[vn]
                char_budget[0] += max(1, len(rep))
                if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                    raise _ShellComplexityBudgetExceeded()
                return rep
            return m.group(0)

        for idx in dollar_indices:
            base_tokens[idx] = _SHELL_VAR_REF_RE.sub(_sub_single, base_tokens[idx])
    expanded_sets: list[list[str]] = [base_tokens]
    for var in multi_vars:
        values = loop_vars[var]
        next_sets: list[list[str]] = []
        for cur_tokens in expanded_sets:
            for val in values:
                if _step_budget is not None:
                    _step_budget[0] += 1
                    if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                        return expanded_sets

                def _sub_multi(m: re.Match[str], _v: str = var, _val: str = val) -> str:
                    if (m.group(1) or m.group(2)) == _v:
                        char_budget[0] += max(1, len(_val))
                        if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                            raise _ShellComplexityBudgetExceeded()
                        return _val
                    return m.group(0)

                new_toks = list(cur_tokens)
                for idx in dollar_indices:
                    tok = new_toks[idx]
                    if "$" in tok:
                        new_tok = _SHELL_VAR_REF_RE.sub(_sub_multi, tok)
                        if new_tok != tok and len(new_tok) > len(val):
                            char_budget[0] += len(new_tok) - len(val)
                            if char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                                raise _ShellComplexityBudgetExceeded()
                        new_toks[idx] = new_tok
                next_sets.append(new_toks)
                if len(next_sets) >= 32:
                    break
            if len(next_sets) >= 32:
                break
        expanded_sets = next_sets
    return expanded_sets


_PRINTF_SPEC_RE = re.compile(r"%(%|[-+ #0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[A-Za-z])")


def _decode_printf_escapes(text: str, *, stop_on_c: bool = True) -> tuple[str, bool]:
    if "\\" not in text:
        return text, False
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == "v":
            out.append("\v")
            i += 2
        elif nxt == "f":
            out.append("\f")
            i += 2
        elif nxt == "b":
            out.append("\b")
            i += 2
        elif nxt == "a":
            out.append("\a")
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        elif nxt == '"':
            out.append('"')
            i += 2
        elif nxt == "'":
            out.append("'")
            i += 2
        elif nxt == "c" and stop_on_c:
            return "".join(out), True
        elif nxt == "x" and i + 2 < n:
            j = i + 2
            while j < n and j < i + 4 and text[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 2:
                out.append(chr(int(text[i + 2 : j], 16)))
                i = j
            else:
                out.append("\\x")
                i += 2
        elif "0" <= nxt <= "7":
            j = i + 1
            if nxt == "0" and j + 1 < n and "0" <= text[j + 1] <= "7":
                j += 1
            end_oct = min(n, j + 3)
            k = j
            while k < end_oct and "0" <= text[k] <= "7":
                k += 1
            out.append(chr(int(text[j:k], 8) & 0xFF))
            i = k
        else:
            out.append("\\")
            out.append(nxt)
            i += 2
    return "".join(out), False


def _format_printf_args(
    args: list[str],
    *,
    _char_budget: list[int] | None = None,
) -> tuple[str, bool]:
    while args:
        if args[0] == "--":
            args = args[1:]
            break
        if args[0] == "-v" and len(args) >= 2:
            args = args[2:]
            continue
        break
    if not args:
        return "", False
    fmt_raw = args[0]
    rest = args[1:]
    decoded_fmt, fmt_stopped = _decode_printf_escapes(fmt_raw, stop_on_c=True)
    out_chunks: list[str] = []
    total_len = 0
    arg_idx = 0
    unsupported = False
    passes = 0
    _SINGLE_PRINTF_MAX_CHARS = 65_536

    while True:
        consumed_any = False
        stopped = False
        idx = 0
        n_fmt = len(decoded_fmt)
        while idx < n_fmt:
            pct = decoded_fmt.find("%", idx)
            if pct == -1:
                lit = decoded_fmt[idx:]
                out_chunks.append(lit)
                total_len += len(lit)
                idx = n_fmt
                break
            if pct > idx:
                lit = decoded_fmt[idx:pct]
                out_chunks.append(lit)
                total_len += len(lit)
            m = _PRINTF_SPEC_RE.match(decoded_fmt, pct)
            if m is None:
                unsupported = True
                out_chunks.append("%")
                total_len += 1
                idx = pct + 1
                continue
            spec_body = m.group(1)
            idx = m.end()
            if spec_body == "%":
                out_chunks.append("%")
                total_len += 1
                continue
            if "*" in spec_body:
                unsupported = True
            spec_ch = spec_body[-1]
            if spec_ch in {
                "s", "b", "c", "q", "d", "i", "u", "o", "x", "X",
                "f", "F", "e", "E", "g", "G", "a", "A",
            }:
                arg_val = rest[arg_idx] if arg_idx < len(rest) else ""
                arg_idx += 1
                consumed_any = True
                if spec_ch == "s":
                    piece = arg_val
                elif spec_ch == "b":
                    piece, stopped = _decode_printf_escapes(arg_val, stop_on_c=True)
                elif spec_ch == "c":
                    piece = arg_val[:1]
                elif spec_ch == "q":
                    piece = shlex.quote(arg_val)
                elif spec_ch in {"d", "i", "u", "o", "x", "X"}:
                    try:
                        num_val = int(arg_val, 0) if arg_val else 0
                    except ValueError:
                        num_val = 0
                    if spec_ch == "u":
                        num_val = num_val & 0xFFFFFFFFFFFFFFFF
                        piece = f"{num_val:d}"
                    elif spec_ch == "o":
                        piece = f"{num_val:o}"
                    elif spec_ch == "x":
                        piece = f"{num_val:x}"
                    elif spec_ch == "X":
                        piece = f"{num_val:X}"
                    else:
                        piece = f"{num_val:d}"
                else:
                    try:
                        f_val = float(arg_val) if arg_val else 0.0
                    except ValueError:
                        f_val = 0.0
                    piece = str(f_val)
                out_chunks.append(piece)
                total_len += len(piece)
            else:
                unsupported = True
                if arg_idx < len(rest):
                    arg_idx += 1
                    consumed_any = True
            if total_len > _SINGLE_PRINTF_MAX_CHARS:
                break
            if stopped:
                break
        if total_len > _SINGLE_PRINTF_MAX_CHARS:
            if idx < n_fmt or arg_idx < len(rest):
                unsupported = True
            if _char_budget is not None:
                _char_budget[0] += total_len
                if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                    raise _ShellComplexityBudgetExceeded()
            break
        passes += 1
        if fmt_stopped or stopped or not consumed_any or arg_idx >= len(rest):
            break
        if passes >= 64:
            unsupported = True
            break
    if _char_budget is not None:
        _char_budget[0] += total_len
        if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
            raise _ShellComplexityBudgetExceeded()
    return "".join(out_chunks), unsupported


def _expand_echo_or_printf_output(
    up_cmd: str,
    raw_args: list[str],
    *,
    _char_budget: list[int] | None = None,
) -> tuple[list[str], bool]:
    args = list(raw_args)
    unsupported = False
    if up_cmd == "echo":
        while args and args[0].startswith("-") and re.fullmatch(r"-[neE]+", args[0]):
            args = args[1:]
        if not args:
            return [], False
        joined = " ".join(args)
        if _char_budget is not None:
            _char_budget[0] += len(joined)
            if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                raise _ShellComplexityBudgetExceeded()
        rendered = (
            joined.replace("\\n", "\n")
            .replace("\\0", "\n")
            .replace("\0", "\n")
            .replace("\\r", "\n")
            .replace("\\t", "\t")
            if ("\\" in joined or "\0" in joined)
            else joined
        )
    elif up_cmd == "printf":
        rendered, unsupported = _format_printf_args(args, _char_budget=_char_budget)
        if not rendered and not unsupported:
            return [], False
    else:
        return [], False
    lines: list[str] = []
    for ln in re.split(r"[\n\r\x00]+", rendered):
        if ln:
            if len(lines) >= 64:
                unsupported = True
                break
            lines.append(ln)
    return lines, unsupported


def _upstream_stage_critical_path(
    stage_tokens: list[str],
    *,
    _char_budget: list[int] | None = None,
) -> str | None:
    if not stage_tokens:
        return None
    up_cmd = _shell_cmd_name(stage_tokens[0])
    if up_cmd == "find":
        start_paths, _ = _extract_find_starting_paths(stage_tokens)
        if not start_paths:
            return "/"
        return next((p for p in start_paths if _is_critical_rm_target(p)), None)
    if up_cmd in {"echo", "printf"}:
        lines, _ = _expand_echo_or_printf_output(
            up_cmd, stage_tokens[1:], _char_budget=_char_budget
        )
        for ln in lines:
            pieces = (
                ln.split()
                if any(ws in ln for ws in (" ", "\t", "\v", "\f"))
                else (ln,)
            )
            for piece in pieces:
                cleaned = piece.strip("\"'")
                if cleaned and _is_critical_rm_target(cleaned):
                    return cleaned
        return None
    if up_cmd == "ls":
        path_args = [t.strip("\"'") for t in stage_tokens[1:] if not t.startswith("-")]
        if not path_args:
            return "/"
        return next((p for p in path_args if _is_critical_rm_target(p)), None)
    return None


def _upstream_stage_emits_critical_path(stage_tokens: list[str]) -> bool:
    return _upstream_stage_critical_path(stage_tokens) is not None


def _space_unquoted_parens(text: str) -> str:
    if "(" not in text and ")" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        if ch in {"(", ")"}:
            out.append(f" {ch} ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_shell_comments(text: str) -> str:
    if "#" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_ansi_single = False
    in_double = False
    unquoted_dollar = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_ansi_single:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                in_ansi_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            unquoted_dollar = False
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "$":
            unquoted_dollar = True
            out.append(ch)
            i += 1
            continue
        if ch == "'":
            if unquoted_dollar:
                if _has_closing_ansi_single_quote(text, i + 1):
                    in_ansi_single = True
            elif text.find("'", i + 1) != -1:
                in_single = True
            unquoted_dollar = False
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            unquoted_dollar = False
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            unquoted_dollar = False
            while i < n and text[i] not in {"\n", "\r"}:
                i += 1
            continue
        unquoted_dollar = False
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_shell_line_continuations(text: str) -> str:
    if "\\\n" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_ansi_single = False
    in_double = False
    in_comment = False
    unquoted_dollar = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_comment:
            out.append(ch)
            if ch in {"\n", "\r"}:
                in_comment = False
                unquoted_dollar = False
            i += 1
            continue
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_ansi_single:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                in_ansi_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == "\n":
                    i += 2
                    continue
                out.append(ch)
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "\n":
                i += 2
                continue
            unquoted_dollar = False
            out.append(ch)
            out.append(nxt)
            i += 2
            continue
        if ch == "$":
            unquoted_dollar = True
            out.append(ch)
            i += 1
            continue
        if ch == "'":
            if unquoted_dollar:
                if _has_closing_ansi_single_quote(text, i + 1):
                    in_ansi_single = True
            elif text.find("'", i + 1) != -1:
                in_single = True
            unquoted_dollar = False
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            unquoted_dollar = False
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (not out or out[-1].isspace() or out[-1] in ";|&()<>"):
            unquoted_dollar = False
            in_comment = True
            out.append(ch)
            i += 1
            continue
        unquoted_dollar = False
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_unquoted_redirections(text: str) -> str:
    if "<" not in text and ">" not in text:
        return text
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "'":
            if text.find("'", i + 1) != -1:
                in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1):
                in_double = True
            out.append(ch)
            i += 1
            continue
        if text.startswith(("<(", ">("), i):
            out.append(ch)
            i += 1
            continue
        m = _SHELL_REDIR_OP_RE.match(text, i)
        if m is not None and (
            text[i] in {"<", ">", "&"}
            or i == 0
            or text[i - 1].isspace()
            or text[i - 1] in ";|&()<>"
        ):
            j = m.end()
            while j < n and text[j] in " \t":
                j += 1
            word_start = j
            w_single = False
            w_double = False
            while j < n:
                wch = text[j]
                if w_single:
                    if wch == "'":
                        w_single = False
                    j += 1
                    continue
                if w_double:
                    if wch == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if wch == '"':
                        w_double = False
                    j += 1
                    continue
                if wch == "\\":
                    if j + 1 >= n:
                        break
                    j += 2
                    continue
                if wch == "'":
                    w_single = True
                    j += 1
                    continue
                if wch == '"':
                    w_double = True
                    j += 1
                    continue
                if wch.isspace() or wch in "<>;|&()":
                    break
                j += 1
            if not w_single and not w_double and j > word_start:
                if out and not out[-1].isspace():
                    out.append(" ")
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)


_MAX_SHELL_WORKLIST_STEPS: int = 65_536
_SHELL_COMPLEXITY_EXCEEDED: object = object()
_SHELL_CHAIN_SEPS: tuple[str, ...] = (";;&", ";;", ";&", "\r\n", "\n", "&&", "||", ";", "&")
_SHELL_PIPE_SEPS: tuple[str, ...] = ("|&", "|")
_SHELL_CASE_END_SEPS: frozenset[str] = frozenset({";;", ";&", ";;&"})

_SHELL_FLOW_PREFIX_TOKENS: frozenset[str] = frozenset(
    {"!", "if", "elif", "while", "until", "do", "then", "else"}
)
_SHELL_FLOW_PREFIX_RE = re.compile(
    r"(?:!|if|elif|while|until|do|then|else)(?:\s+|(?=[({]))"
    r"|time(?:\s+-p)*(?:\s+(?!-)|(?=[({]))"
)


def _strip_leading_shell_keywords_span(text: str, start: int, end: int) -> int:
    cur = start
    while cur < end and text[cur].isspace():
        cur += 1
    while cur < end:
        m = _SHELL_FLOW_PREFIX_RE.match(text, cur, end)
        if m is None:
            break
        cur = m.end()
        while cur < end and text[cur].isspace():
            cur += 1
    return cur


def _strip_leading_shell_keywords(text: str) -> str:
    start = _strip_leading_shell_keywords_span(text, 0, len(text))
    return text[start:].strip()


def _strip_case_header_span(text: str, start: int, end: int) -> int | None:
    cur = start
    while cur < end and text[cur].isspace():
        cur += 1
    if not text.startswith("case", cur) or cur + 4 >= end or not text[cur + 4].isspace():
        return None
    i = cur + 4
    while i < end and text[i].isspace():
        i += 1
    word_start = i
    in_single = False
    in_double = False
    while i < end:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < end:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            i += 2 if i + 1 < end else 1
            continue
        if ch == "'":
            if text.find("'", i + 1, end) != -1:
                in_single = True
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1, end):
                in_double = True
            i += 1
            continue
        if ch.isspace() or ch in ";|&()":
            break
        i += 1
    if in_single or in_double or i == word_start:
        return None
    while i < end and text[i].isspace():
        i += 1
    if not text.startswith("in", i):
        return None
    after_in = i + 2
    if after_in < end and not text[after_in].isspace() and text[after_in] not in "(;":
        return None
    while after_in < end and text[after_in].isspace():
        after_in += 1
    return after_in


def _strip_case_pattern_span(
    text: str, start: int, end: int, pairs: dict[int, int]
) -> int | None:
    cur = start
    while cur < end and text[cur].isspace():
        cur += 1
    if cur >= end:
        return None
    if text[cur] == "(" and cur in pairs and pairs[cur] < end:
        j = pairs[cur] + 1
        while j < end and text[j].isspace():
            j += 1
        return j
    in_single = False
    in_double = False
    i = cur
    while i < end:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < end:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            i += 2 if i + 1 < end else 1
            continue
        if ch == "'":
            if text.find("'", i + 1, end) != -1:
                in_single = True
            i += 1
            continue
        if ch == '"':
            if _has_closing_double_quote(text, i + 1, end):
                in_double = True
            i += 1
            continue
        if i in pairs and pairs[i] < end:
            i = pairs[i] + 1
            continue
        if ch == ")":
            j = i + 1
            while j < end and text[j].isspace():
                j += 1
            return j
        i += 1
    return None


def _strip_esac_prefix_span(text: str, start: int, end: int) -> int | None:
    cur = start
    while cur < end and text[cur].isspace():
        cur += 1
    if not text.startswith("esac", cur):
        return None
    after = cur + 4
    if after < end and not text[after].isspace():
        return None
    while after < end and text[after].isspace():
        after += 1
    return after


def _unwrap_span_groups(
    text: str, start: int, end: int, pairs: dict[int, int]
) -> tuple[int, int, bool]:
    cur_s = start
    cur_e = end
    unwrapped_any = False
    while True:
        cur_s = _strip_leading_shell_keywords_span(text, cur_s, cur_e)
        while cur_e > cur_s and text[cur_e - 1].isspace():
            cur_e -= 1
        if cur_e - cur_s < 2 or text[cur_s] not in {"(", "{"}:
            break
        close_idx = pairs.get(cur_s)
        if close_idx is None or close_idx >= cur_e:
            break
        if close_idx == cur_e - 1:
            cur_s += 1
            cur_e -= 1
            unwrapped_any = True
            continue
        if _is_shell_redirection_tail(text[close_idx + 1 : cur_e]):
            cur_s += 1
            cur_e = close_idx
            unwrapped_any = True
            continue
        break
    while cur_s < cur_e and text[cur_s].isspace():
        cur_s += 1
    while cur_e > cur_s and text[cur_e - 1].isspace():
        cur_e -= 1
    return cur_s, cur_e, unwrapped_any


_SPLIT_SCAN_GRP_RE = re.compile(r"""[\\'"#(){};\r\n&|]""")
_SPLIT_SCAN_NOGRP_RE = re.compile(r"""[\\'"#;\r\n&|]""")


def _split_span_outside_quotes(
    text: str,
    start: int,
    end: int,
    seps: tuple[str, ...],
    pairs: dict[int, int],
    closers: set[int],
    *,
    respect_groups: bool = True,
) -> list[tuple[int, int, str | None]]:
    if (
        seps is _SHELL_PIPE_SEPS
        and text.find("'", start, end) == -1
        and text.find('"', start, end) == -1
        and text.find("\\", start, end) == -1
        and text.find("#", start, end) == -1
        and text.find("&", start, end) == -1
        and text.find(">", start, end) == -1
        and text.find("||", start, end) == -1
        and (
            not respect_groups
            or (text.find("(", start, end) == -1 and text.find("{", start, end) == -1)
        )
    ):
        parts_fast: list[tuple[int, int, str | None]] = []
        p_s = start
        while True:
            pipe_idx = text.find("|", p_s, end)
            if pipe_idx == -1:
                parts_fast.append((p_s, end, None))
                return parts_fast
            parts_fast.append((p_s, pipe_idx, "|"))
            p_s = pipe_idx + 1

    ordered_seps = tuple(sorted(seps, key=len, reverse=True))
    scan_re = _SPLIT_SCAN_GRP_RE if respect_groups else _SPLIT_SCAN_NOGRP_RE
    group_depth = 0
    parts: list[tuple[int, int, str | None]] = []
    part_start = start
    prev_was_escaped = False
    pending_op_continuation = False
    i = start
    while i < end:
        m = scan_re.search(text, i, end)
        if m is None:
            break
        pos = m.start()
        if pos > i:
            if pending_op_continuation:
                for k in range(i, pos):
                    if text[k] not in " \t":
                        pending_op_continuation = False
                        break
            prev_was_escaped = False
            i = pos
        ch = text[i]
        if ch == "\\":
            if i + 1 < end:
                nxt_ch = text[i + 1]
                prev_was_escaped = nxt_ch not in {"\n", "\r"}
                if nxt_ch not in {"\n", "\r"}:
                    pending_op_continuation = False
                i += 2
            else:
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
            continue
        if ch == "'":
            close_sq = text.find("'", i + 1, end)
            i = close_sq + 1 if close_sq != -1 else i + 1
            prev_was_escaped = False
            pending_op_continuation = False
            continue
        if ch == '"':
            close_dq = _find_closing_double_quote(text, i + 1, end)
            i = close_dq + 1 if close_dq != -1 else i + 1
            prev_was_escaped = False
            pending_op_continuation = False
            continue
        if ch == "#" and (i == start or text[i - 1].isspace() or text[i - 1] in ";|&()<>"):
            nl = text.find("\n", i + 1, end)
            cr = text.find("\r", i + 1, end)
            if nl == -1:
                i = cr if cr != -1 else end
            elif cr == -1:
                i = nl
            else:
                i = nl if nl < cr else cr
            prev_was_escaped = False
            continue
        if respect_groups:
            if group_depth == 0 and i in pairs and pairs[i] < end:
                i = pairs[i] + 1
                prev_was_escaped = False
                pending_op_continuation = False
                continue
            if i in pairs:
                group_depth += 1
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
                continue
            if i in closers:
                group_depth = max(0, group_depth - 1)
                prev_was_escaped = False
                pending_op_continuation = False
                i += 1
                continue
        if (not respect_groups or group_depth == 0) and ch in {";", "\r", "\n", "&", "|"}:
            if "|" in ordered_seps and "||" not in ordered_seps and text.startswith("||", i, end):
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "&" in ordered_seps and "|&" not in ordered_seps and text.startswith("|&", i, end):
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "&&" not in ordered_seps and text.startswith("&&", i, end):
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            if "||" not in ordered_seps and text.startswith("||", i, end):
                prev_was_escaped = False
                pending_op_continuation = True
                i += 2
                continue
            matched_sep: str | None = None
            for sep in ordered_seps:
                if text.startswith(sep, i, end):
                    if sep == "|" and i > start and text[i - 1] == ">" and not prev_was_escaped:
                        continue
                    if sep == "&" and (
                        (i > start and text[i - 1] in {">", "<", "|"} and not prev_was_escaped)
                        or text.startswith("&>", i, end)
                    ):
                        continue
                    matched_sep = sep
                    break
            if matched_sep is not None:
                if matched_sep in {"\n", "\r\n"} and pending_op_continuation:
                    prev_was_escaped = False
                    i += len(matched_sep)
                    continue
                parts.append((part_start, i, matched_sep))
                part_start = i + len(matched_sep)
                prev_was_escaped = False
                pending_op_continuation = False
                i = part_start
                continue
        if ch == "|" and not (i > start and text[i - 1] == ">" and not prev_was_escaped):
            pending_op_continuation = True
        else:
            pending_op_continuation = False
        prev_was_escaped = False
        i += 1
    parts.append((part_start, end, None))
    return parts


def _parse_single_stage_tokens(stage_str: str) -> list[str]:
    s = stage_str.strip()
    if not s:
        return []
    if not any(c in s for c in "'\"\\#()<>;|&${}"):
        return _unwrap_command_tokens(s.split())
    if "\\\n" in s:
        s = _strip_shell_line_continuations(s)
    if "$'" in s:
        s = _normalize_ansi_c_quotes(s)
    if '$"' in s:
        s = _normalize_locale_dquotes(s)
    if "#" in s:
        s = _strip_shell_comments(s)
    s = _strip_unquoted_redirections(s)
    spaced = _space_unquoted_parens(s)
    try:
        raw_tokens = _posix_shlex_split(spaced)
    except ValueError:
        raw_tokens = spaced.split()
    while raw_tokens and (
        raw_tokens[0] in {"(", "{"}
        or (raw_tokens[0] in _SHELL_FLOW_PREFIX_TOKENS and len(raw_tokens) > 1)
    ):
        raw_tokens.pop(0)
    while raw_tokens and raw_tokens[-1] in {")", "}"}:
        raw_tokens.pop()
    return _unwrap_command_tokens(raw_tokens)


def _parse_stage_cached(stage_str: str, cache: dict[str, list[str]]) -> list[str]:
    key = stage_str.strip()
    if not key:
        return []
    cached = cache.get(key)
    if cached is not None:
        return cached
    toks = _parse_single_stage_tokens(key)
    if len(cache) < 8192:
        cache[key] = toks
    return toks


def _extract_for_loop_binding(
    text: str,
    start: int,
    end: int,
    pairs: dict[int, int],
    effective_pos_samples: list[str] | None,
    positional_sample: str | None,
    *,
    _step_budget: list[int] | None = None,
) -> tuple[str, list[str]] | None:
    i = start
    while i < end:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(" and (i not in pairs or pairs[i] >= end):
            i += 1
            continue
        if (
            ch == "{"
            and (i + 1 == end or text[i + 1].isspace())
            and (i not in pairs or pairs[i] >= end)
        ):
            i += 1
            continue
        break
    if not text.startswith("for", i, end) or i + 3 >= end or not text[i + 3].isspace():
        return None
    stripped_chain = text[i:end].strip()
    m_for_in = re.match(
        r"^for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+(.*)$", stripped_chain, re.DOTALL
    )
    if m_for_in is not None:
        var_name = m_for_in.group(1)
        words_raw = m_for_in.group(2).strip()
        try:
            words = _posix_shlex_split(words_raw)
        except ValueError:
            words = words_raw.split()
        expanded_words: list[str] = []
        for word in words:
            if word in {"$@", "${@}", "$*", "${*}"}:
                if effective_pos_samples is not None:
                    if (
                        _step_budget is not None
                        and _step_budget[0] + len(expanded_words) + len(effective_pos_samples)
                        > _MAX_SHELL_WORKLIST_STEPS
                    ):
                        needed = max(
                            1,
                            _MAX_SHELL_WORKLIST_STEPS - _step_budget[0] - len(expanded_words) + 1,
                        )
                        expanded_words.extend(effective_pos_samples[:needed])
                        break
                    expanded_words.extend(effective_pos_samples)
                else:
                    expanded_words.append(word)
            elif word in {"$1", "${1}"}:
                if effective_pos_samples:
                    expanded_words.append(effective_pos_samples[0])
                else:
                    expanded_words.append(word)
            elif word in {"$0", "${0}"}:
                if positional_sample is not None:
                    expanded_words.append(positional_sample)
                else:
                    expanded_words.append(word)
            else:
                expanded_words.append(word)
        return var_name, expanded_words
    m_for_bare = re.match(r"^for\s+([A-Za-z_][A-Za-z0-9_]*)$", stripped_chain)
    if m_for_bare is not None:
        if effective_pos_samples is not None:
            return m_for_bare.group(1), list(effective_pos_samples)
        return m_for_bare.group(1), []
    return None


def _strip_case_prefix_in_chain(
    text: str,
    start: int,
    end: int,
    pairs: dict[int, int],
    case_depth: int,
    expect_case_pattern: bool,
) -> tuple[int, int, bool]:
    c_s = _strip_leading_shell_keywords_span(text, start, end)
    while c_s < end:
        if case_depth > 0 and (esac_next := _strip_esac_prefix_span(text, c_s, end)) is not None:
            case_depth -= 1
            expect_case_pattern = False
            c_s = _strip_leading_shell_keywords_span(text, esac_next, end)
            continue
        if expect_case_pattern:
            pat_next = _strip_case_pattern_span(text, c_s, end, pairs)
            if pat_next is not None:
                expect_case_pattern = False
                c_s = _strip_leading_shell_keywords_span(text, pat_next, end)
                continue
        if (case_next := _strip_case_header_span(text, c_s, end)) is not None:
            case_depth += 1
            expect_case_pattern = True
            c_s = _strip_leading_shell_keywords_span(text, case_next, end)
            continue
        break
    return c_s, case_depth, expect_case_pattern


def _loop_vars_cache_key(
    u_start: int, u_end: int, loop_vars: Mapping[str, list[str]]
) -> tuple[int, int, tuple[tuple[str, tuple[str, ...]], ...]]:
    if not loop_vars:
        return (u_start, u_end, ())
    return (u_start, u_end, tuple(sorted((k, tuple(v)) for k, v in loop_vars.items())))


_STDIN_PASSTHROUGH_CMDS: frozenset[str] = frozenset(
    {
        "cat",
        "tac",
        "tee",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "sed",
        "awk",
        "gawk",
        "mawk",
        "sort",
        "uniq",
        "head",
        "tail",
        "cut",
        "tr",
        "nl",
        "fold",
        "fmt",
        "strings",
        "shuf",
        "dos2unix",
        "iconv",
        "pv",
    }
)


def _group_is_stdin_passthrough(
    text: str,
    root_start: int,
    root_end: int,
    pairs: dict[int, int],
    closers: set[int],
    parsed_tok_cache: dict[str, list[str]],
    *,
    _step_budget: list[int],
) -> bool | object:
    work: list[tuple[int, int]] = [(root_start, root_end)]
    visited = 0
    while work:
        visited += 1
        _step_budget[0] += 1
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            return _SHELL_COMPLEXITY_EXCEEDED
        if visited > 64:
            return False
        cur_s, cur_e = work.pop()
        u_s, u_e, _ = _unwrap_span_groups(text, cur_s, cur_e, pairs)
        if u_s >= u_e:
            return False
        chains = _split_span_outside_quotes(
            text, u_s, u_e, _SHELL_CHAIN_SEPS, pairs, closers, respect_groups=True
        )
        non_empty = [(cs, ce) for cs, ce, _ in chains if text[cs:ce].strip()]
        if len(non_empty) != 1:
            return False
        c_s, c_e = non_empty[0]
        g_s, g_e, unwrapped_chain = _unwrap_span_groups(text, c_s, c_e, pairs)
        if unwrapped_chain:
            work.append((g_s, g_e))
            continue
        pipe_stages = _split_span_outside_quotes(
            text, c_s, c_e, _SHELL_PIPE_SEPS, pairs, closers, respect_groups=True
        )
        if not pipe_stages:
            return False
        for p_s, p_e, _ in pipe_stages:
            sg_s, sg_e, is_grp = _unwrap_span_groups(text, p_s, p_e, pairs)
            if is_grp:
                work.append((sg_s, sg_e))
            else:
                toks = _parse_stage_cached(text[p_s:p_e], parsed_tok_cache)
                if not toks or _shell_cmd_name(toks[0]) not in _STDIN_PASSTHROUGH_CMDS:
                    return False
    return True


def _find_group_upstream_critical_path(
    text: str,
    root_start: int,
    root_end: int,
    pairs: dict[int, int],
    closers: set[int],
    parsed_tok_cache: dict[str, list[str]],
    group_crit_cache: dict[
        tuple[int, int, tuple[tuple[str, tuple[str, ...]], ...]], str | None
    ],
    *,
    effective_pos_samples: list[str] | None,
    positional_sample: str | None,
    loop_vars: Mapping[str, list[str]],
    has_for_keyword: bool = True,
    _step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
) -> str | None | object:
    if _step_budget is None:
        _step_budget = [0]
    if _char_budget is None:
        _char_budget = [0]
    dfs_stack: list[
        tuple[str, int, int, dict[str, list[str]], tuple[int, int, tuple[Any, ...]] | None]
    ] = [
        ("visit", root_start, root_end, dict(loop_vars), None),
    ]
    while dfs_stack:
        _step_budget[0] += 1
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            return _SHELL_COMPLEXITY_EXCEEDED
        kind, s_pos, e_pos, cur_lvars, finish_key = dfs_stack.pop()
        if kind == "finish":
            if finish_key is not None and finish_key not in group_crit_cache:
                group_crit_cache[finish_key] = None
            continue
        u_s, u_e, _ = _unwrap_span_groups(text, s_pos, e_pos, pairs)
        if u_s >= u_e:
            continue
        ckey = _loop_vars_cache_key(u_s, u_e, cur_lvars)
        if ckey in group_crit_cache:
            cached_crit = group_crit_cache[ckey]
            if cached_crit is not None:
                return cached_crit
            continue
        dfs_stack.append(("finish", u_s, u_e, cur_lvars, ckey))
        child_groups: list[tuple[int, int, dict[str, list[str]]]] = []
        block_lvars = dict(cur_lvars)
        case_depth = 0
        expect_case_pattern = False
        has_inner_groups = bool(pairs) and (
            text.find("(", u_s, u_e) != -1 or text.find("{", u_s, u_e) != -1
        )
        chains = _split_span_outside_quotes(
            text, u_s, u_e, _SHELL_CHAIN_SEPS, pairs, closers, respect_groups=True
        )
        for c_start, c_end, trailing_sep in chains:
            _step_budget[0] += 1
            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                return _SHELL_COMPLEXITY_EXCEEDED
            c_e = c_end
            c_s, case_depth, expect_case_pattern = _strip_case_prefix_in_chain(
                text, c_start, c_e, pairs, case_depth, expect_case_pattern
            )
            while c_e > c_s and text[c_e - 1].isspace():
                c_e -= 1
            if c_s < c_e:
                for_binding = (
                    _extract_for_loop_binding(
                        text,
                        c_s,
                        c_e,
                        pairs,
                        effective_pos_samples,
                        positional_sample,
                        _step_budget=_step_budget,
                    )
                    if has_for_keyword
                    else None
                )
                if for_binding is not None:
                    var_name, expanded_words = for_binding
                    _step_budget[0] += len(expanded_words)
                    if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                        return _SHELL_COMPLEXITY_EXCEEDED
                    if expanded_words or var_name not in block_lvars:
                        block_lvars = dict(block_lvars)
                        block_lvars[var_name] = expanded_words
                else:
                    if has_inner_groups:
                        g_s, g_e, unwrapped_chain = _unwrap_span_groups(text, c_s, c_e, pairs)
                    else:
                        g_s, g_e, unwrapped_chain = c_s, c_e, False
                    if unwrapped_chain:
                        child_groups.append((g_s, g_e, block_lvars))
                    else:
                        pipe_stages = _split_span_outside_quotes(
                            text, c_s, c_e, _SHELL_PIPE_SEPS, pairs, closers, respect_groups=True
                        )
                        for p_s, p_e, _ in pipe_stages:
                            _step_budget[0] += 1
                            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                return _SHELL_COMPLEXITY_EXCEEDED
                            if has_inner_groups:
                                sg_s, sg_e, is_grp = _unwrap_span_groups(text, p_s, p_e, pairs)
                            else:
                                sg_s, sg_e, is_grp = p_s, p_e, False
                            if is_grp:
                                child_groups.append((sg_s, sg_e, block_lvars))
                            else:
                                toks = _parse_stage_cached(text[p_s:p_e], parsed_tok_cache)
                                if toks:
                                    expanded_list = (
                                        _expand_loop_var_tokens(
                                            toks,
                                            block_lvars,
                                            _step_budget=_step_budget,
                                            _char_budget=_char_budget,
                                        )
                                        if block_lvars
                                        else (toks,)
                                    )
                                    for expanded_up in expanded_list:
                                        _step_budget[0] += 1
                                        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                            return _SHELL_COMPLEXITY_EXCEEDED
                                        crit_p = _upstream_stage_critical_path(
                                            expanded_up, _char_budget=_char_budget
                                        )
                                        if crit_p is not None:
                                            group_crit_cache[ckey] = crit_p
                                            return crit_p
            if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                expect_case_pattern = True
        for cg_s, cg_e, cg_lvars in reversed(child_groups):
            dfs_stack.append(("visit", cg_s, cg_e, cg_lvars, None))
    return None


_CHMOD_OCTAL_MODE_RE = re.compile(r"[0-7]{3,4}")
_CHMOD_SYM_CLAUSE_RE = re.compile(r"([ugoa]*)(?:[+=][rwxXst]*)+")


def _is_permissive_chmod_mode(mode_tok: str) -> bool:
    low = mode_tok.strip("\"'").lower()
    if not low:
        return False
    if _CHMOD_OCTAL_MODE_RE.fullmatch(low) is not None:
        return (int(low[-1]) & 2) != 0
    if "," in low or "+" in low or "=" in low:
        for part in low.split(","):
            m = _CHMOD_SYM_CLAUSE_RE.fullmatch(part)
            if m is None:
                continue
            scope = m.group(1)
            if ("a" in scope or "o" in scope) and re.search(r"[+=][rwxXst]*w", part) is not None:
                return True
    return False


def _check_chmod_tokens(tokens: list[str]) -> str | None:
    has_recursive = False
    permissive_mode = False
    targets: list[str] = []
    after_dash_dash = False
    seen_mode = False
    for tok in tokens[1:]:
        clean_tok = tok.strip("\"'")
        low_tok = clean_tok.lower()
        if not after_dash_dash:
            if clean_tok == "--":
                after_dash_dash = True
                continue
            if low_tok == "--recursive" or (
                clean_tok.startswith("-")
                and not clean_tok.startswith("--")
                and "r" in low_tok[1:]
            ):
                has_recursive = True
                continue
            if clean_tok.startswith("-"):
                continue
        if not seen_mode and _is_permissive_chmod_mode(clean_tok):
            permissive_mode = True
            seen_mode = True
            continue
        seen_mode = True
        targets.append(clean_tok)
    if has_recursive and permissive_mode:
        for target in targets:
            if target.startswith("/*") or _is_critical_rm_target(target):
                return "safety_floor:destructive_chmod_777_root"
    return None


def _extract_xargs_echo_samples(
    prev_tokens: list[str],
    loop_vars: Mapping[str, list[str]],
    *,
    _step_budget: list[int],
    _char_budget: list[int],
) -> tuple[list[tuple[str | None, list[str]]], bool]:
    if not prev_tokens:
        return [], False
    expanded_prevs: Sequence[list[str]] = (
        _expand_loop_var_tokens(
            prev_tokens,
            loop_vars,
            _step_budget=_step_budget,
            _char_budget=_char_budget,
        )
        if loop_vars
        else (prev_tokens,)
    )
    samples: list[tuple[str | None, list[str]]] = []
    seen_lines: set[str] = set()
    batch_count = 0
    has_unsupported = False
    for toks in expanded_prevs:
        if not toks:
            continue
        up_cmd = _shell_cmd_name(toks[0])
        if up_cmd not in {"echo", "printf"}:
            continue
        lines, unsupported = _expand_echo_or_printf_output(
            up_cmd, toks[1:], _char_budget=_char_budget
        )
        if unsupported:
            has_unsupported = True
        if not lines:
            continue
        all_words: list[str] = []
        for ln in lines:
            raw_words = [
                w.strip("\"'")
                for w in ln.split()
                if w.strip("\"'")
            ]
            if len(raw_words) > 64:
                has_unsupported = True
                ln_words = raw_words[:64]
            else:
                ln_words = raw_words
            if not ln_words:
                ln_words = [ln]
            for w in ln_words:
                if len(all_words) >= 64:
                    has_unsupported = True
                    break
                all_words.append(w)
            if ln not in seen_lines:
                if len(seen_lines) < 64:
                    seen_lines.add(ln)
                    samples.append((ln, ln_words))
                else:
                    has_unsupported = True
        if len(lines) > 1 and all_words:
            if batch_count < 64:
                samples.append((None, all_words))
                batch_count += 1
            else:
                has_unsupported = True
    return samples, has_unsupported


def _find_group_upstream_echo_samples(
    text: str,
    root_start: int,
    root_end: int,
    pairs: dict[int, int],
    closers: set[int],
    parsed_tok_cache: dict[str, list[str]],
    *,
    effective_pos_samples: list[str] | None,
    positional_sample: str | None,
    loop_vars: Mapping[str, list[str]],
    has_for_keyword: bool,
    _step_budget: list[int],
    _char_budget: list[int],
) -> tuple[list[tuple[str | None, list[str]]], bool]:
    work: list[tuple[int, int, dict[str, list[str]]]] = [
        (root_start, root_end, dict(loop_vars))
    ]
    visited = 0
    samples: list[tuple[str | None, list[str]]] = []
    seen_lines: set[str] = set()
    batch_count = 0
    has_unsupported = False
    while work:
        if len(seen_lines) >= 64:
            has_unsupported = True
            break
        visited += 1
        _step_budget[0] += 1
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            raise _ShellComplexityBudgetExceeded()
        if visited > 64:
            has_unsupported = True
            break
        s_pos, e_pos, cur_lvars = work.pop()
        u_s, u_e, _ = _unwrap_span_groups(text, s_pos, e_pos, pairs)
        if u_s >= u_e:
            continue
        block_lvars = dict(cur_lvars)
        case_depth = 0
        expect_case_pattern = False
        has_inner_groups = bool(pairs) and (
            text.find("(", u_s, u_e) != -1 or text.find("{", u_s, u_e) != -1
        )
        chains = _split_span_outside_quotes(
            text, u_s, u_e, _SHELL_CHAIN_SEPS, pairs, closers, respect_groups=True
        )
        for c_start, c_end, trailing_sep in chains:
            _step_budget[0] += 1
            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                raise _ShellComplexityBudgetExceeded()
            c_e = c_end
            c_s, case_depth, expect_case_pattern = _strip_case_prefix_in_chain(
                text, c_start, c_e, pairs, case_depth, expect_case_pattern
            )
            while c_e > c_s and text[c_e - 1].isspace():
                c_e -= 1
            if c_s < c_e:
                for_binding = (
                    _extract_for_loop_binding(
                        text,
                        c_s,
                        c_e,
                        pairs,
                        effective_pos_samples,
                        positional_sample,
                        _step_budget=_step_budget,
                    )
                    if has_for_keyword
                    else None
                )
                if for_binding is not None:
                    var_name, expanded_words = for_binding
                    _step_budget[0] += len(expanded_words)
                    if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                        raise _ShellComplexityBudgetExceeded()
                    if expanded_words or var_name not in block_lvars:
                        block_lvars = dict(block_lvars)
                        block_lvars[var_name] = expanded_words
                else:
                    if has_inner_groups:
                        g_s, g_e, unwrapped_chain = _unwrap_span_groups(text, c_s, c_e, pairs)
                    else:
                        g_s, g_e, unwrapped_chain = c_s, c_e, False
                    if unwrapped_chain:
                        work.append((g_s, g_e, block_lvars))
                    else:
                        pipe_stages = _split_span_outside_quotes(
                            text, c_s, c_e, _SHELL_PIPE_SEPS, pairs, closers, respect_groups=True
                        )
                        for p_s, p_e, _ in reversed(pipe_stages):
                            _step_budget[0] += 1
                            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                raise _ShellComplexityBudgetExceeded()
                            if has_inner_groups:
                                sg_s, sg_e, is_grp = _unwrap_span_groups(text, p_s, p_e, pairs)
                            else:
                                sg_s, sg_e, is_grp = p_s, p_e, False
                            if is_grp:
                                is_pt = _group_is_stdin_passthrough(
                                    text,
                                    sg_s,
                                    sg_e,
                                    pairs,
                                    closers,
                                    parsed_tok_cache,
                                    _step_budget=_step_budget,
                                )
                                if is_pt is _SHELL_COMPLEXITY_EXCEEDED:
                                    raise _ShellComplexityBudgetExceeded()
                                if is_pt:
                                    continue
                                work.append((sg_s, sg_e, block_lvars))
                                break
                            toks = _parse_stage_cached(text[p_s:p_e], parsed_tok_cache)
                            if not toks:
                                break
                            up_cmd = _shell_cmd_name(toks[0])
                            if up_cmd in {"echo", "printf"}:
                                sub_samples, sub_unsup = _extract_xargs_echo_samples(
                                    toks,
                                    block_lvars,
                                    _step_budget=_step_budget,
                                    _char_budget=_char_budget,
                                )
                                if sub_unsup:
                                    has_unsupported = True
                                for line_s, w_list in sub_samples:
                                    if line_s is None:
                                        if batch_count < 64:
                                            samples.append((None, w_list))
                                            batch_count += 1
                                        else:
                                            has_unsupported = True
                                    elif line_s not in seen_lines:
                                        if len(seen_lines) < 64:
                                            seen_lines.add(line_s)
                                            samples.append((line_s, w_list))
                                        else:
                                            has_unsupported = True
                                break
                            if up_cmd in _STDIN_PASSTHROUGH_CMDS:
                                continue
                            break
            if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                expect_case_pattern = True
    return samples, has_unsupported


def _collect_upstream_xargs_echo_samples(
    text: str,
    target_stage_idx: int,
    stage_entries: list[tuple[bool, int, int, list[str]]],
    pairs: dict[int, int],
    closers: set[int],
    parsed_tok_cache: dict[str, list[str]],
    *,
    effective_pos_samples: list[str] | None,
    positional_sample: str | None,
    loop_vars: Mapping[str, list[str]],
    has_for_keyword: bool,
    inherited_echo_samples: list[tuple[str | None, list[str]]] | None,
    inherited_unsupported: bool,
    _step_budget: list[int],
    _char_budget: list[int],
) -> tuple[list[tuple[str | None, list[str]]], bool]:
    idx = target_stage_idx - 1
    while idx >= 0:
        _step_budget[0] += 1
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            raise _ShellComplexityBudgetExceeded()
        up_is_grp, up_s, up_e, up_toks = stage_entries[idx]
        if up_is_grp:
            is_pt = _group_is_stdin_passthrough(
                text,
                up_s,
                up_e,
                pairs,
                closers,
                parsed_tok_cache,
                _step_budget=_step_budget,
            )
            if is_pt is _SHELL_COMPLEXITY_EXCEEDED:
                raise _ShellComplexityBudgetExceeded()
            if is_pt:
                idx -= 1
                continue
            return _find_group_upstream_echo_samples(
                text,
                up_s,
                up_e,
                pairs,
                closers,
                parsed_tok_cache,
                effective_pos_samples=effective_pos_samples,
                positional_sample=positional_sample,
                loop_vars=loop_vars,
                has_for_keyword=has_for_keyword,
                _step_budget=_step_budget,
                _char_budget=_char_budget,
            )
        if not up_toks:
            return [], False
        up_cmd = _shell_cmd_name(up_toks[0])
        if up_cmd in {"echo", "printf"}:
            return _extract_xargs_echo_samples(
                up_toks,
                loop_vars,
                _step_budget=_step_budget,
                _char_budget=_char_budget,
            )
        if up_cmd in _STDIN_PASSTHROUGH_CMDS:
            idx -= 1
            continue
        return [], False
    if inherited_echo_samples is not None or inherited_unsupported:
        return list(inherited_echo_samples or []), inherited_unsupported
    return [], False


def _inspect_python_stage_tokens(
    tokens: list[str],
    *,
    _ast_depth: int,
    _cmd_depth: int,
    _step_budget: list[int],
    _ast_step_budget: list[int],
    _char_budget: list[int],
    _seen_texts: set[str] | None,
    _truncated_out: list[bool] | None = None,
) -> str | None:
    if not tokens:
        return None
    cmd = _shell_cmd_name(tokens[0])
    if not _is_python_cmd_name(cmd):
        return None
    script_idx, inline_script = _find_python_c_script(tokens)
    if script_idx is None:
        return None
    if _ast_depth >= 4:
        if _truncated_out is not None:
            _truncated_out[0] = True
        return "safety_floor:python_ast_complexity_budget_exceeded"
    py_script = inline_script if inline_script is not None else tokens[script_idx]
    if _seen_texts is not None and py_script in _seen_texts:
        return None
    trunc_flag = [False]
    violation = _check_text_against_safety_patterns(
        py_script,
        _ast_depth=_ast_depth + 1,
        _cmd_depth=_cmd_depth + 1,
        _step_budget=_step_budget,
        _ast_step_budget=_ast_step_budget,
        _char_budget=_char_budget,
        _seen_texts=_seen_texts,
        _truncated_out=trunc_flag,
    )
    if trunc_flag[0] and _truncated_out is not None:
        _truncated_out[0] = True
    if violation is not None:
        return violation
    if (
        _seen_texts is not None
        and _ast_depth == 0
        and _cmd_depth == 0
        and not trunc_flag[0]
    ):
        _seen_texts.add(py_script)
    return None


def _check_expanded_subcommand(
    sub_cmd: str,
    *,
    _cmd_depth: int,
    _ast_depth: int,
    _positional_sample: str | None = None,
    _positional_samples: list[str] | None = None,
    _step_budget: list[int],
    _ast_step_budget: list[int],
    _char_budget: list[int],
    _seen_texts: set[str] | None,
    _truncated_out: list[bool] | None = None,
) -> str | None:
    pattern_violation = _match_safety_patterns(sub_cmd)
    if pattern_violation is not None:
        return pattern_violation
    if any(w in sub_cmd.lower() for w in _PYTHON_AST_TRIGGER_WORDS):
        ast_violation, _ = _check_python_ast_calls_impl(
            sub_cmd,
            _ast_depth=_ast_depth,
            _ast_step_budget=_ast_step_budget,
            _step_budget=_step_budget,
            _char_budget=_char_budget,
            _cmd_depth=_cmd_depth + 1,
            _seen_texts=_seen_texts,
            _truncated_out=_truncated_out,
        )
        if ast_violation is not None:
            return ast_violation
    return _check_deobfuscated_commands_impl(
        sub_cmd,
        _cmd_depth=_cmd_depth + 1,
        _ast_depth=_ast_depth,
        _positional_sample=_positional_sample,
        _positional_samples=_positional_samples,
        _step_budget=_step_budget,
        _ast_step_budget=_ast_step_budget,
        _char_budget=_char_budget,
        _seen_texts=_seen_texts,
        _truncated_out=_truncated_out,
    )


def _check_deobfuscated_commands(
    segment_source: str,
    *,
    _cmd_depth: int = 0,
    _ast_depth: int = 0,
    _group_depth: int = 0,
    _respect_groups: bool = True,
    _positional_sample: str | None = None,
    _positional_samples: list[str] | None = None,
    _loop_vars: Mapping[str, list[str]] | None = None,
    _step_budget: list[int] | None = None,
    _ast_step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
    _seen_texts: set[str] | None = None,
    _truncated_out: list[bool] | None = None,
) -> str | None:
    try:
        return _check_deobfuscated_commands_impl(
            segment_source,
            _cmd_depth=_cmd_depth,
            _ast_depth=_ast_depth,
            _group_depth=_group_depth,
            _respect_groups=_respect_groups,
            _positional_sample=_positional_sample,
            _positional_samples=_positional_samples,
            _loop_vars=_loop_vars,
            _step_budget=_step_budget,
            _ast_step_budget=_ast_step_budget,
            _char_budget=_char_budget,
            _seen_texts=_seen_texts,
            _truncated_out=_truncated_out,
        )
    except _ShellComplexityBudgetExceeded:
        return "safety_floor:shell_complexity_budget_exceeded"


def _check_deobfuscated_commands_impl(
    segment_source: str,
    *,
    _cmd_depth: int = 0,
    _ast_depth: int = 0,
    _group_depth: int = 0,
    _respect_groups: bool = True,
    _positional_sample: str | None = None,
    _positional_samples: list[str] | None = None,
    _loop_vars: Mapping[str, list[str]] | None = None,
    _step_budget: list[int] | None = None,
    _ast_step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
    _seen_texts: set[str] | None = None,
    _truncated_out: list[bool] | None = None,
) -> str | None:
    if _step_budget is None:
        _step_budget = [0]
    if _ast_step_budget is None:
        _ast_step_budget = [0]
    if _char_budget is None:
        _char_budget = [0]
    if _cmd_depth > 0:
        _step_budget[0] += 16
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            return "safety_floor:shell_complexity_budget_exceeded"
    segment_normalized = False
    if "\\\n" in segment_source:
        segment_source = _strip_shell_line_continuations(segment_source)
        segment_normalized = True
    if "$'" in segment_source:
        segment_source = _normalize_ansi_c_quotes(segment_source)
        segment_normalized = True
    if '$"' in segment_source:
        segment_source = _normalize_locale_dquotes(segment_source)
        segment_normalized = True
    effective_pos_samples: list[str] | None = (
        list(_positional_samples)
        if _positional_samples is not None
        else ([_positional_sample] if _positional_sample is not None else None)
    )
    pairs, closers = _match_shell_groups(segment_source)
    has_for_keyword = "for" in segment_source
    parsed_tok_cache: dict[str, list[str]] = {}
    group_crit_cache: dict[
        tuple[int, int, tuple[tuple[str, tuple[str, ...]], ...]], str | None
    ] = {}
    init_loop_vars: dict[str, list[str]] = (
        {k: list(v) for k, v in _loop_vars.items()} if _loop_vars else {}
    )
    worklist: list[
        tuple[
            int,
            int,
            dict[str, list[str]],
            str | None,
            list[tuple[str | None, list[str]]] | None,
            bool,
        ]
    ] = [(0, len(segment_source), init_loop_vars, None, None, False)]

    while worklist:
        _step_budget[0] += 1
        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
            return "safety_floor:shell_complexity_budget_exceeded"
        (
            cur_start,
            cur_end,
            cur_loop_vars,
            inherited_upstream_crit,
            inherited_echo_samples,
            inherited_echo_unsupported,
        ) = worklist.pop()
        u_start, u_end, _ = _unwrap_span_groups(segment_source, cur_start, cur_end, pairs)
        if u_start >= u_end:
            continue
        chains = _split_span_outside_quotes(
            segment_source,
            u_start,
            u_end,
            _SHELL_CHAIN_SEPS,
            pairs,
            closers,
            respect_groups=_respect_groups,
        )
        loop_vars = cur_loop_vars
        case_depth = 0
        expect_case_pattern = False

        for c_start, c_end, trailing_sep in chains:
            _step_budget[0] += 1
            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                return "safety_floor:shell_complexity_budget_exceeded"
            c_e = c_end
            c_s, case_depth, expect_case_pattern = _strip_case_prefix_in_chain(
                segment_source, c_start, c_e, pairs, case_depth, expect_case_pattern
            )
            while c_e > c_s and segment_source[c_e - 1].isspace():
                c_e -= 1
            if c_s >= c_e:
                if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                    expect_case_pattern = True
                continue

            for_binding = (
                _extract_for_loop_binding(
                    segment_source,
                    c_s,
                    c_e,
                    pairs,
                    effective_pos_samples,
                    _positional_sample,
                    _step_budget=_step_budget,
                )
                if has_for_keyword
                else None
            )
            if for_binding is not None:
                var_name, expanded_words = for_binding
                _step_budget[0] += len(expanded_words)
                if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                    return "safety_floor:shell_complexity_budget_exceeded"
                if expanded_words or var_name not in loop_vars:
                    loop_vars = dict(loop_vars)
                    loop_vars[var_name] = expanded_words
                if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                    expect_case_pattern = True
                continue

            if _respect_groups:
                g_s, g_e, unwrapped_chain = _unwrap_span_groups(
                    segment_source, c_s, c_e, pairs
                )
                if unwrapped_chain:
                    worklist.append(
                        (
                            g_s,
                            g_e,
                            loop_vars,
                            inherited_upstream_crit,
                            inherited_echo_samples,
                            inherited_echo_unsupported,
                        )
                    )
                    if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                        expect_case_pattern = True
                    continue

            pipe_stages = _split_span_outside_quotes(
                segment_source,
                c_s,
                c_e,
                _SHELL_PIPE_SEPS,
                pairs,
                closers,
                respect_groups=_respect_groups,
            )
            stage_entries: list[tuple[bool, int, int, list[str]]] = []
            pending_subgroups: list[tuple[int, int, int, dict[str, list[str]]]] = []
            for stage_pos, (p_s, p_e, _) in enumerate(pipe_stages):
                _step_budget[0] += 1
                if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                    return "safety_floor:shell_complexity_budget_exceeded"
                if _respect_groups:
                    sg_s, sg_e, is_grp = _unwrap_span_groups(segment_source, p_s, p_e, pairs)
                    if is_grp:
                        pending_subgroups.append((stage_pos, sg_s, sg_e, loop_vars))
                        stage_entries.append((True, sg_s, sg_e, []))
                        continue
                toks = _parse_stage_cached(segment_source[p_s:p_e], parsed_tok_cache)
                stage_entries.append((False, p_s, p_e, toks))

            running_upstream_critical_path: str | None = None
            inherited_active_crit: str | None = inherited_upstream_crit
            upstream_scanned_until = 0

            def _advance_upstream_critical_path(
                target_stage_idx: int,
                cur_stage_entries: list[tuple[bool, int, int, list[str]]],
                cur_lvars: Mapping[str, list[str]],
            ) -> object:
                nonlocal running_upstream_critical_path, inherited_active_crit
                nonlocal upstream_scanned_until
                while (
                    running_upstream_critical_path is None
                    and upstream_scanned_until < target_stage_idx
                ):
                    up_is_grp, up_s, up_e, up_toks = cur_stage_entries[upstream_scanned_until]
                    upstream_scanned_until += 1
                    if up_is_grp:
                        grp_crit = _find_group_upstream_critical_path(
                            segment_source,
                            up_s,
                            up_e,
                            pairs,
                            closers,
                            parsed_tok_cache,
                            group_crit_cache,
                            effective_pos_samples=effective_pos_samples,
                            positional_sample=_positional_sample,
                            loop_vars=cur_lvars,
                            has_for_keyword=has_for_keyword,
                            _step_budget=_step_budget,
                            _char_budget=_char_budget,
                        )
                        if grp_crit is _SHELL_COMPLEXITY_EXCEEDED:
                            return _SHELL_COMPLEXITY_EXCEEDED
                        if isinstance(grp_crit, str):
                            running_upstream_critical_path = grp_crit
                            inherited_active_crit = None
                        elif inherited_active_crit is not None:
                            is_pt = _group_is_stdin_passthrough(
                                segment_source,
                                up_s,
                                up_e,
                                pairs,
                                closers,
                                parsed_tok_cache,
                                _step_budget=_step_budget,
                            )
                            if is_pt is _SHELL_COMPLEXITY_EXCEEDED:
                                return _SHELL_COMPLEXITY_EXCEEDED
                            if not is_pt:
                                inherited_active_crit = None
                    elif up_toks:
                        found_crit = False
                        expanded_ups = (
                            _expand_loop_var_tokens(
                                up_toks,
                                cur_lvars,
                                _step_budget=_step_budget,
                                _char_budget=_char_budget,
                            )
                            if cur_lvars
                            else (up_toks,)
                        )
                        for expanded_up in expanded_ups:
                            _step_budget[0] += 1
                            if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                return _SHELL_COMPLEXITY_EXCEEDED
                            p_crit = _upstream_stage_critical_path(
                                expanded_up, _char_budget=_char_budget
                            )
                            if p_crit is not None:
                                running_upstream_critical_path = p_crit
                                inherited_active_crit = None
                                found_crit = True
                                break
                        if (
                            not found_crit
                            and inherited_active_crit is not None
                            and _shell_cmd_name(up_toks[0]) not in _STDIN_PASSTHROUGH_CMDS
                        ):
                            inherited_active_crit = None
                return None

            resolved_subgroups: list[
                tuple[
                    int,
                    int,
                    dict[str, list[str]],
                    str | None,
                    list[tuple[str | None, list[str]]] | None,
                    bool,
                ]
            ] = []
            for sg_stage_idx, sg_s, sg_e, sg_lvars in pending_subgroups:
                sg_inherited: str | None = None
                sg_echo: list[tuple[str | None, list[str]]] | None = None
                sg_unsup = False
                if sg_stage_idx == 0:
                    sg_inherited = inherited_upstream_crit
                    sg_echo = inherited_echo_samples
                    sg_unsup = inherited_echo_unsupported
                else:
                    if (
                        _advance_upstream_critical_path(sg_stage_idx, stage_entries, sg_lvars)
                        is _SHELL_COMPLEXITY_EXCEEDED
                    ):
                        return "safety_floor:shell_complexity_budget_exceeded"
                    sg_inherited = (
                        running_upstream_critical_path
                        if running_upstream_critical_path is not None
                        else inherited_active_crit
                    )
                    sub_slice_low = segment_source[sg_s:sg_e].lower()
                    if "xargs" in sub_slice_low or (
                        "x" in sub_slice_low
                        and "rgs" in sub_slice_low
                        and any(q in sub_slice_low for q in ("'", '"', "\\", "$"))
                    ):
                        sg_echo, sg_unsup = _collect_upstream_xargs_echo_samples(
                            segment_source,
                            sg_stage_idx,
                            stage_entries,
                            pairs,
                            closers,
                            parsed_tok_cache,
                            effective_pos_samples=effective_pos_samples,
                            positional_sample=_positional_sample,
                            loop_vars=sg_lvars,
                            has_for_keyword=has_for_keyword,
                            inherited_echo_samples=inherited_echo_samples,
                            inherited_unsupported=inherited_echo_unsupported,
                            _step_budget=_step_budget,
                            _char_budget=_char_budget,
                        )
                resolved_subgroups.append(
                    (sg_s, sg_e, sg_lvars, sg_inherited, sg_echo, sg_unsup)
                )
            for sg_item in reversed(resolved_subgroups):
                worklist.append(sg_item)

            for stage_idx, (is_grp, _st_s, _st_e, base_tokens) in enumerate(stage_entries):
                if is_grp or not base_tokens:
                    continue
                expanded_stage_tokens = (
                    _expand_loop_var_tokens(
                        base_tokens,
                        loop_vars,
                        _step_budget=_step_budget,
                        _char_budget=_char_budget,
                    )
                    if loop_vars
                    else (base_tokens,)
                )
                for tokens in expanded_stage_tokens:
                    _step_budget[0] += 1
                    if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                        return "safety_floor:shell_complexity_budget_exceeded"
                    if loop_vars and tokens is not base_tokens and tokens:
                        first_head = _shell_cmd_name(tokens[0])
                        if first_head in _WRAPPER_COMMANDS or (
                            "=" in tokens[0]
                            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]) is not None
                        ):
                            tokens = _unwrap_command_tokens(tokens)
                            if not tokens:
                                continue
                    raw_stage_slice = segment_source[_st_s:_st_e]
                    if (
                        tokens is not base_tokens
                        or _cmd_depth > 0
                        or segment_normalized
                        or any(ch in raw_stage_slice for ch in ("'", '"', "\\", "$"))
                    ):
                        stage_pattern_violation = _match_safety_patterns(" ".join(tokens))
                        if stage_pattern_violation is not None:
                            return stage_pattern_violation
                    cmd = _shell_cmd_name(tokens[0])
                    if cmd == "rm":
                        has_recursive, has_force, targets = _parse_rm_tokens(tokens[1:])
                        rm_violation = _check_rm_targets(has_recursive, has_force, targets)
                        if rm_violation is not None:
                            return rm_violation

                    elif cmd == "find":
                        starting_paths, expr_idx = _extract_find_starting_paths(tokens)
                        has_critical_start = (not starting_paths) or any(
                            _is_critical_rm_target(p) for p in starting_paths
                        )
                        if "-delete" in tokens[1:] and has_critical_start:
                            return "safety_floor:destructive_rm_root_or_glob"
                        j = expr_idx
                        while j < len(tokens):
                            if tokens[j].lower() in {"-exec", "-execdir", "-ok", "-okdir"}:
                                inner_raw: list[str] = []
                                k = j + 1
                                while k < len(tokens):
                                    t = tokens[k]
                                    if t in {"+", ";", r"\;", "\\"}:
                                        break
                                    inner_raw.append(t)
                                    k += 1
                                j = k + 1
                                inner = _unwrap_command_tokens(inner_raw)
                                if not inner:
                                    continue
                                inner_cmd = Path(inner[0].strip("\"'")).name.lower()
                                sample_path = next(
                                    (p for p in starting_paths if _is_critical_rm_target(p)),
                                    starting_paths[0] if starting_paths else "/",
                                )
                                if inner_cmd == "rm":
                                    has_rec, has_frc, rm_targets = _parse_rm_tokens(inner[1:])
                                    explicit_targets: list[str] = []
                                    uses_placeholder = False
                                    for tgt in rm_targets:
                                        if "{}" in tgt:
                                            uses_placeholder = True
                                            stripped_tgt = tgt.replace("{}", "").rstrip("/")
                                            if stripped_tgt:
                                                explicit_targets.append(stripped_tgt)
                                        else:
                                            explicit_targets.append(tgt)
                                    explicit_violation = _check_rm_targets(
                                        has_rec, has_frc, explicit_targets
                                    )
                                    if explicit_violation is not None:
                                        return explicit_violation
                                    if has_critical_start and (
                                        has_rec or has_frc or uses_placeholder
                                    ):
                                        return "safety_floor:destructive_rm_root_or_glob"
                                elif (
                                    inner_cmd in {"sh", "bash", "dash", "zsh", "ksh"}
                                    and (script_idx := _find_sh_c_script_index(inner)) is not None
                                ):
                                    if _cmd_depth >= 3:
                                        if _truncated_out is not None:
                                            _truncated_out[0] = True
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                    extra_args = inner[script_idx + 1 :]
                                    if extra_args:
                                        _step_budget[0] += len(extra_args)
                                        if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                            return "safety_floor:shell_complexity_budget_exceeded"
                                    _char_budget[0] += len(inner[script_idx])
                                    if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                    sub_cmd = _bounded_str_replace(
                                        inner[script_idx], "{}", sample_path, _char_budget
                                    )
                                    resolved_pos: list[str] = []
                                    if extra_args:
                                        resolved_pos = [
                                            _bounded_str_replace(
                                                arg, "{}", sample_path, _char_budget
                                            )
                                            for arg in extra_args
                                        ]
                                        sub_cmd = _replace_shell_positional_params(
                                            sub_cmd, resolved_pos, _char_budget=_char_budget
                                        )
                                        if len(resolved_pos) > 1:
                                            if "$" in sub_cmd and (
                                                "@" in sub_cmd or "*" in sub_cmd
                                            ):
                                                need_at = (
                                                    "@" in sub_cmd
                                                    and _SHELL_PARAM_AT_RAW_RE.search(sub_cmd)
                                                    is not None
                                                )
                                                need_star = (
                                                    "*" in sub_cmd
                                                    and _SHELL_PARAM_STAR_RAW_RE.search(sub_cmd)
                                                    is not None
                                                )
                                                if need_at or need_star:
                                                    arg_chars = (
                                                        sum(
                                                            len(a) + 3 * a.count("'") + 2
                                                            for a in resolved_pos[1:]
                                                        )
                                                        if need_at
                                                        else sum(len(a) for a in resolved_pos[1:])
                                                    )
                                                    if (
                                                        _char_budget[0] + arg_chars
                                                        > _MAX_SHELL_EXPANDED_CHARS
                                                    ):
                                                        return (
                                                            "safety_floor:"
                                                            "shell_complexity_budget_exceeded"
                                                        )
                                                    at_val = (
                                                        " ".join(
                                                            shlex.quote(a)
                                                            for a in resolved_pos[1:]
                                                        )
                                                        if need_at
                                                        else None
                                                    )
                                                    star_val = (
                                                        " ".join(resolved_pos[1:])
                                                        if need_star
                                                        else None
                                                    )
                                                    sub_cmd = _replace_shell_at_star_params(
                                                        sub_cmd,
                                                        at_val=at_val,
                                                        star_val=star_val,
                                                        quote_at=False,
                                                        _char_budget=_char_budget,
                                                    )
                                        elif any("{}" in arg for arg in extra_args):
                                            sub_cmd = _replace_shell_at_star_params(
                                                sub_cmd,
                                                at_val=sample_path,
                                                star_val=sample_path,
                                                quote_at=True,
                                                _char_budget=_char_budget,
                                            )
                                    else:
                                        sub_cmd = _replace_shell_positional_params(
                                            sub_cmd,
                                            (sample_path, sample_path),
                                            _char_budget=_char_budget,
                                        )
                                        sub_cmd = _replace_shell_at_star_params(
                                            sub_cmd,
                                            at_val=sample_path,
                                            star_val=sample_path,
                                            quote_at=True,
                                            _char_budget=_char_budget,
                                        )
                                    has_placeholder_arg = (not extra_args) or any(
                                        "{}" in arg for arg in extra_args
                                    )
                                    find_pos_samples = (
                                        resolved_pos[1:]
                                        if len(resolved_pos) > 1
                                        else ([sample_path] if has_placeholder_arg else [])
                                    )
                                    sub_violation = _check_expanded_subcommand(
                                        sub_cmd,
                                        _cmd_depth=_cmd_depth,
                                        _ast_depth=_ast_depth,
                                        _positional_sample=sample_path,
                                        _positional_samples=find_pos_samples,
                                        _step_budget=_step_budget,
                                        _ast_step_budget=_ast_step_budget,
                                        _char_budget=_char_budget,
                                        _seen_texts=_seen_texts,
                                        _truncated_out=_truncated_out,
                                    )
                                    if sub_violation is not None:
                                        return sub_violation
                                else:
                                    exec_tokens = [
                                        (
                                            _bounded_str_replace(
                                                tok, "{}", sample_path, _char_budget
                                            )
                                            if "{}" in tok
                                            else tok
                                        )
                                        for tok in inner
                                    ]
                                    if exec_tokens and "{}" in inner[0]:
                                        exec_tokens = _unwrap_command_tokens(exec_tokens)
                                    if exec_tokens:
                                        exec_pattern_violation = _match_safety_patterns(
                                            " ".join(exec_tokens)
                                        )
                                        if exec_pattern_violation is not None:
                                            return exec_pattern_violation
                                        if _shell_cmd_name(exec_tokens[0]) == "chmod":
                                            chmod_violation = _check_chmod_tokens(exec_tokens)
                                            if chmod_violation is not None:
                                                return chmod_violation
                                        py_violation = _inspect_python_stage_tokens(
                                            exec_tokens,
                                            _ast_depth=_ast_depth,
                                            _cmd_depth=_cmd_depth,
                                            _step_budget=_step_budget,
                                            _ast_step_budget=_ast_step_budget,
                                            _char_budget=_char_budget,
                                            _seen_texts=_seen_texts,
                                            _truncated_out=_truncated_out,
                                        )
                                        if py_violation is not None:
                                            return py_violation
                                continue
                            j += 1

                    elif cmd == "xargs":
                        xargs_inner_raw, xargs_replace_str = _extract_xargs_inner_and_replace(
                            tokens[1:]
                        )
                        xargs_inner = _unwrap_command_tokens(xargs_inner_raw)
                        if xargs_inner:
                            xargs_cmd = _shell_cmd_name(xargs_inner[0])
                            is_xargs_shell = xargs_cmd in {"sh", "bash", "dash", "zsh", "ksh"}
                            is_xargs_danger_sink = (
                                xargs_cmd
                                in {
                                    "rm",
                                    "chmod",
                                    "dd",
                                    "git",
                                    "psql",
                                    "mysql",
                                    "sqlite3",
                                    "mkfs",
                                    "wipefs",
                                    "fdisk",
                                    "parted",
                                }
                                or _is_python_cmd_name(xargs_cmd)
                                or is_xargs_shell
                            )
                            needs_upstream = (
                                is_xargs_danger_sink
                                or xargs_replace_str is not None
                                or any("{}" in tok for tok in xargs_inner)
                            )
                            upstream_critical_path: str | None = None
                            echo_samples: list[tuple[str | None, list[str]]] = []
                            echo_unsupported = False
                            if needs_upstream:
                                if stage_idx > 0 and (
                                    _advance_upstream_critical_path(
                                        stage_idx, stage_entries, loop_vars
                                    )
                                    is _SHELL_COMPLEXITY_EXCEEDED
                                ):
                                    return "safety_floor:shell_complexity_budget_exceeded"
                                upstream_critical_path = (
                                    running_upstream_critical_path
                                    if running_upstream_critical_path is not None
                                    else inherited_active_crit
                                )
                            if xargs_cmd == "rm":
                                has_rec, has_frc, rm_targets = _parse_rm_tokens(xargs_inner[1:])
                                explicit_targets = [
                                    t
                                    for t in rm_targets
                                    if "{}" not in t
                                    and (not xargs_replace_str or xargs_replace_str not in t)
                                ]
                                explicit_violation = _check_rm_targets(
                                    has_rec, has_frc, explicit_targets
                                )
                                if explicit_violation is not None:
                                    return explicit_violation
                                if (has_rec or has_frc) and upstream_critical_path is not None:
                                    return "safety_floor:destructive_rm_root_or_glob"
                                if (
                                    stage_idx > 0
                                    or inherited_echo_samples is not None
                                    or inherited_echo_unsupported
                                ):
                                    echo_samples, echo_unsupported = (
                                        _collect_upstream_xargs_echo_samples(
                                            segment_source,
                                            stage_idx,
                                            stage_entries,
                                            pairs,
                                            closers,
                                            parsed_tok_cache,
                                            effective_pos_samples=effective_pos_samples,
                                            positional_sample=_positional_sample,
                                            loop_vars=loop_vars,
                                            has_for_keyword=has_for_keyword,
                                            inherited_echo_samples=inherited_echo_samples,
                                            inherited_unsupported=inherited_echo_unsupported,
                                            _step_budget=_step_budget,
                                            _char_budget=_char_budget,
                                        )
                                    )
                                    if echo_unsupported:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                    has_placeholder = xargs_replace_str is not None or any(
                                        "{}" in tok for tok in xargs_inner
                                    )
                                    for line_s, w_list in echo_samples:
                                        if has_placeholder:
                                            if line_s is None:
                                                continue
                                            rm_args = [
                                                (
                                                    _bounded_str_replace(
                                                        _bounded_str_replace(
                                                            tok, "{}", line_s, _char_budget
                                                        ),
                                                        xargs_replace_str,
                                                        line_s,
                                                        _char_budget,
                                                    )
                                                    if (
                                                        xargs_replace_str
                                                        and xargs_replace_str != "{}"
                                                    )
                                                    else _bounded_str_replace(
                                                        tok, "{}", line_s, _char_budget
                                                    )
                                                )
                                                for tok in xargs_inner[1:]
                                            ]
                                        elif w_list:
                                            rm_args = [*xargs_inner[1:], *w_list]
                                        else:
                                            continue
                                        comb_rec, comb_frc, comb_tgts = _parse_rm_tokens(rm_args)
                                        comb_viol = _check_rm_targets(
                                            comb_rec, comb_frc, comb_tgts
                                        )
                                        if comb_viol is not None:
                                            return comb_viol
                            elif (
                                is_xargs_shell
                                and (script_idx := _find_sh_c_script_index(xargs_inner))
                                is not None
                            ):
                                if _cmd_depth >= 3:
                                    if _truncated_out is not None:
                                        _truncated_out[0] = True
                                    return "safety_floor:shell_complexity_budget_exceeded"
                                if (
                                    stage_idx > 0
                                    or inherited_echo_samples is not None
                                    or inherited_echo_unsupported
                                ):
                                    echo_samples, echo_unsupported = (
                                        _collect_upstream_xargs_echo_samples(
                                            segment_source,
                                            stage_idx,
                                            stage_entries,
                                            pairs,
                                            closers,
                                            parsed_tok_cache,
                                            effective_pos_samples=effective_pos_samples,
                                            positional_sample=_positional_sample,
                                            loop_vars=loop_vars,
                                            has_for_keyword=has_for_keyword,
                                            inherited_echo_samples=inherited_echo_samples,
                                            inherited_unsupported=inherited_echo_unsupported,
                                            _step_budget=_step_budget,
                                            _char_budget=_char_budget,
                                        )
                                    )
                                    if echo_unsupported:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                xargs_sample_candidates: list[str] = []
                                seen_x_cand: set[str] = set()
                                if upstream_critical_path is not None:
                                    xargs_sample_candidates.append(upstream_critical_path)
                                    seen_x_cand.add(upstream_critical_path)
                                for line_s, _ in echo_samples:
                                    if line_s is not None and line_s not in seen_x_cand:
                                        seen_x_cand.add(line_s)
                                        xargs_sample_candidates.append(line_s)
                                if not xargs_sample_candidates:
                                    xargs_sample_candidates = ["/tmp/work"]
                                extra_args = xargs_inner[script_idx + 1 :]
                                if extra_args:
                                    _step_budget[0] += len(extra_args)
                                    if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                for xargs_sample in xargs_sample_candidates:
                                    _char_budget[0] += len(xargs_inner[script_idx])
                                    if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                    sub_cmd = _bounded_str_replace(
                                        xargs_inner[script_idx], "{}", xargs_sample, _char_budget
                                    )
                                    if xargs_replace_str and xargs_replace_str != "{}":
                                        sub_cmd = _bounded_str_replace(
                                            sub_cmd, xargs_replace_str, xargs_sample, _char_budget
                                        )
                                    if extra_args:
                                        resolved_pos = [
                                            (
                                                _bounded_str_replace(
                                                    _bounded_str_replace(
                                                        arg, "{}", xargs_sample, _char_budget
                                                    ),
                                                    xargs_replace_str,
                                                    xargs_sample,
                                                    _char_budget,
                                                )
                                                if xargs_replace_str and xargs_replace_str != "{}"
                                                else _bounded_str_replace(
                                                    arg, "{}", xargs_sample, _char_budget
                                                )
                                            )
                                            for arg in extra_args
                                        ]
                                        if xargs_replace_str is None:
                                            resolved_pos = [
                                                resolved_pos[0],
                                                *resolved_pos[1:],
                                                xargs_sample,
                                            ]
                                    elif xargs_replace_str is None:
                                        resolved_pos = [xargs_sample, xargs_sample]
                                    else:
                                        resolved_pos = []

                                    sub_cmd = _replace_shell_positional_params(
                                        sub_cmd, resolved_pos, _char_budget=_char_budget
                                    )
                                    if (
                                        len(resolved_pos) > 1
                                        and "$" in sub_cmd
                                        and ("@" in sub_cmd or "*" in sub_cmd)
                                    ):
                                        need_at = (
                                            "@" in sub_cmd
                                            and _SHELL_PARAM_AT_RAW_RE.search(sub_cmd) is not None
                                        )
                                        need_star = (
                                            "*" in sub_cmd
                                            and _SHELL_PARAM_STAR_RAW_RE.search(sub_cmd)
                                            is not None
                                        )
                                        if need_at or need_star:
                                            arg_chars = (
                                                sum(
                                                    len(a) + 3 * a.count("'") + 2
                                                    for a in resolved_pos[1:]
                                                )
                                                if need_at
                                                else sum(len(a) for a in resolved_pos[1:])
                                            )
                                            if (
                                                _char_budget[0] + arg_chars
                                                > _MAX_SHELL_EXPANDED_CHARS
                                            ):
                                                return (
                                                    "safety_floor:"
                                                    "shell_complexity_budget_exceeded"
                                                )
                                            at_val = (
                                                " ".join(
                                                    shlex.quote(a) for a in resolved_pos[1:]
                                                )
                                                if need_at
                                                else None
                                            )
                                            star_val = (
                                                " ".join(resolved_pos[1:]) if need_star else None
                                            )
                                            sub_cmd = _replace_shell_at_star_params(
                                                sub_cmd,
                                                at_val=at_val,
                                                star_val=star_val,
                                                quote_at=False,
                                                _char_budget=_char_budget,
                                            )
                                    xargs_pos_samples = resolved_pos[1:]
                                    pos_sample = (
                                        xargs_sample
                                        if (
                                            xargs_replace_str is None
                                            or any(xargs_sample == p for p in xargs_pos_samples)
                                        )
                                        else None
                                    )
                                    sub_violation = _check_expanded_subcommand(
                                        sub_cmd,
                                        _cmd_depth=_cmd_depth,
                                        _ast_depth=_ast_depth,
                                        _positional_sample=pos_sample,
                                        _positional_samples=xargs_pos_samples,
                                        _step_budget=_step_budget,
                                        _ast_step_budget=_ast_step_budget,
                                        _char_budget=_char_budget,
                                        _seen_texts=_seen_texts,
                                        _truncated_out=_truncated_out,
                                    )
                                    if sub_violation is not None:
                                        return sub_violation
                            else:
                                if needs_upstream and (
                                    stage_idx > 0
                                    or inherited_echo_samples is not None
                                    or inherited_echo_unsupported
                                ):
                                    echo_samples, echo_unsupported = (
                                        _collect_upstream_xargs_echo_samples(
                                            segment_source,
                                            stage_idx,
                                            stage_entries,
                                            pairs,
                                            closers,
                                            parsed_tok_cache,
                                            effective_pos_samples=effective_pos_samples,
                                            positional_sample=_positional_sample,
                                            loop_vars=loop_vars,
                                            has_for_keyword=has_for_keyword,
                                            inherited_echo_samples=inherited_echo_samples,
                                            inherited_unsupported=inherited_echo_unsupported,
                                            _step_budget=_step_budget,
                                            _char_budget=_char_budget,
                                        )
                                    )
                                    if echo_unsupported and is_xargs_danger_sink:
                                        return "safety_floor:shell_complexity_budget_exceeded"
                                has_placeholder = xargs_replace_str is not None or any(
                                    "{}" in tok for tok in xargs_inner
                                )
                                candidate_batches: list[tuple[str | None, list[str]]] = []
                                seen_batch_lines: set[str] = set()
                                if upstream_critical_path is not None:
                                    candidate_batches.append(
                                        (upstream_critical_path, [upstream_critical_path])
                                    )
                                    seen_batch_lines.add(upstream_critical_path)
                                for line_s, word_list in echo_samples:
                                    if line_s is None:
                                        candidate_batches.append((None, word_list))
                                    elif line_s not in seen_batch_lines:
                                        seen_batch_lines.add(line_s)
                                        candidate_batches.append((line_s, word_list))
                                if not candidate_batches:
                                    candidate_batches = [(None, [])]
                                for line_sample, word_list in candidate_batches:
                                    if has_placeholder and line_sample is not None:
                                        xargs_tokens: list[str] = []
                                        for tok in xargs_inner:
                                            t_exp = (
                                                _bounded_str_replace(
                                                    tok, "{}", line_sample, _char_budget
                                                )
                                                if "{}" in tok
                                                else tok
                                            )
                                            if (
                                                xargs_replace_str
                                                and xargs_replace_str != "{}"
                                                and xargs_replace_str in t_exp
                                            ):
                                                t_exp = _bounded_str_replace(
                                                    t_exp,
                                                    xargs_replace_str,
                                                    line_sample,
                                                    _char_budget,
                                                )
                                            xargs_tokens.append(t_exp)
                                        if xargs_tokens and (
                                            "{}" in xargs_inner[0]
                                            or (
                                                xargs_replace_str
                                                and xargs_replace_str in xargs_inner[0]
                                            )
                                        ):
                                            xargs_tokens = _unwrap_command_tokens(xargs_tokens)
                                    elif not has_placeholder and word_list:
                                        xargs_tokens = [*xargs_inner, *word_list]
                                    else:
                                        xargs_tokens = xargs_inner
                                    if xargs_tokens:
                                        x_pat_violation = _match_safety_patterns(
                                            " ".join(xargs_tokens)
                                        )
                                        if x_pat_violation is not None:
                                            return x_pat_violation
                                        if _shell_cmd_name(xargs_tokens[0]) == "chmod":
                                            chmod_violation = _check_chmod_tokens(xargs_tokens)
                                            if chmod_violation is not None:
                                                return chmod_violation
                                        py_violation = _inspect_python_stage_tokens(
                                            xargs_tokens,
                                            _ast_depth=_ast_depth,
                                            _cmd_depth=_cmd_depth,
                                            _step_budget=_step_budget,
                                            _ast_step_budget=_ast_step_budget,
                                            _char_budget=_char_budget,
                                            _seen_texts=_seen_texts,
                                            _truncated_out=_truncated_out,
                                        )
                                        if py_violation is not None:
                                            return py_violation

                    elif cmd == "chmod":
                        chmod_violation = _check_chmod_tokens(tokens)
                        if chmod_violation is not None:
                            return chmod_violation

                    elif cmd in {"sh", "bash", "dash", "zsh", "ksh"}:
                        if stage_idx > 0:
                            return "safety_floor:shell_pipe_to_interpreter"
                        if (script_idx := _find_sh_c_script_index(tokens)) is not None:
                            if _cmd_depth >= 3:
                                if _truncated_out is not None:
                                    _truncated_out[0] = True
                                return "safety_floor:shell_complexity_budget_exceeded"
                            sub_cmd = tokens[script_idx]
                            extra_args = tokens[script_idx + 1 :]
                            sh_pos_samples: list[str] = []
                            if extra_args:
                                _step_budget[0] += len(extra_args)
                                if _step_budget[0] > _MAX_SHELL_WORKLIST_STEPS:
                                    return "safety_floor:shell_complexity_budget_exceeded"
                            _char_budget[0] += len(sub_cmd)
                            if _char_budget[0] > _MAX_SHELL_EXPANDED_CHARS:
                                return "safety_floor:shell_complexity_budget_exceeded"
                            sub_cmd = _replace_shell_positional_params(
                                sub_cmd, extra_args, _char_budget=_char_budget
                            )
                            if len(extra_args) > 1:
                                if "$" in sub_cmd and ("@" in sub_cmd or "*" in sub_cmd):
                                    need_at = (
                                        "@" in sub_cmd
                                        and _SHELL_PARAM_AT_RAW_RE.search(sub_cmd) is not None
                                    )
                                    need_star = (
                                        "*" in sub_cmd
                                        and _SHELL_PARAM_STAR_RAW_RE.search(sub_cmd) is not None
                                    )
                                    if need_at or need_star:
                                        arg_chars = (
                                            sum(
                                                len(a) + 3 * a.count("'") + 2
                                                for a in extra_args[1:]
                                            )
                                            if need_at
                                            else sum(len(a) for a in extra_args[1:])
                                        )
                                        if _char_budget[0] + arg_chars > _MAX_SHELL_EXPANDED_CHARS:
                                            return "safety_floor:shell_complexity_budget_exceeded"
                                        at_val = (
                                            " ".join(shlex.quote(a) for a in extra_args[1:])
                                            if need_at
                                            else None
                                        )
                                        star_val = (
                                            " ".join(extra_args[1:]) if need_star else None
                                        )
                                        sub_cmd = _replace_shell_at_star_params(
                                            sub_cmd,
                                            at_val=at_val,
                                            star_val=star_val,
                                            quote_at=False,
                                            _char_budget=_char_budget,
                                        )
                                sh_pos_samples = list(extra_args[1:])
                            sub_violation = _check_expanded_subcommand(
                                sub_cmd,
                                _cmd_depth=_cmd_depth,
                                _ast_depth=_ast_depth,
                                _positional_sample=sh_pos_samples[0] if sh_pos_samples else None,
                                _positional_samples=sh_pos_samples or None,
                                _step_budget=_step_budget,
                                _ast_step_budget=_ast_step_budget,
                                _char_budget=_char_budget,
                                _seen_texts=_seen_texts,
                                _truncated_out=_truncated_out,
                            )
                            if sub_violation is not None:
                                return sub_violation

                    elif _is_python_cmd_name(cmd):
                        py_violation = _inspect_python_stage_tokens(
                            tokens,
                            _ast_depth=_ast_depth,
                            _cmd_depth=_cmd_depth,
                            _step_budget=_step_budget,
                            _ast_step_budget=_ast_step_budget,
                            _char_budget=_char_budget,
                            _seen_texts=_seen_texts,
                            _truncated_out=_truncated_out,
                        )
                        if py_violation is not None:
                            return py_violation

            if case_depth > 0 and trailing_sep in _SHELL_CASE_END_SEPS:
                expect_case_pattern = True
    return None


def _check_text_against_safety_patterns(
    text: str,
    *,
    _ast_depth: int = 0,
    _cmd_depth: int = 0,
    _step_budget: list[int] | None = None,
    _ast_step_budget: list[int] | None = None,
    _char_budget: list[int] | None = None,
    _seen_texts: set[str] | None = None,
    _truncated_out: list[bool] | None = None,
) -> str | None:
    if _step_budget is None:
        _step_budget = [0]
    if _ast_step_budget is None:
        _ast_step_budget = [0]
    if _char_budget is None:
        _char_budget = [0]
    pattern_violation = _match_safety_patterns(text)
    if pattern_violation is not None:
        return pattern_violation
    ast_violation, is_python_module = _check_python_ast_calls_impl(
        text,
        _ast_depth=_ast_depth,
        _ast_step_budget=_ast_step_budget,
        _step_budget=_step_budget,
        _char_budget=_char_budget,
        _cmd_depth=_cmd_depth,
        _seen_texts=_seen_texts,
        _truncated_out=_truncated_out,
    )
    if ast_violation is not None:
        return ast_violation
    if is_python_module:
        return None
    return _check_deobfuscated_commands(
        text,
        _cmd_depth=_cmd_depth,
        _ast_depth=_ast_depth,
        _step_budget=_step_budget,
        _ast_step_budget=_ast_step_budget,
        _char_budget=_char_budget,
        _seen_texts=_seen_texts,
        _truncated_out=_truncated_out,
    )


def _iter_strings(value: Any, *, key_hint: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((key_hint, value))
    elif isinstance(value, Mapping):
        for k, v in value.items():
            found.extend(_iter_strings(v, key_hint=str(k).lower()))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_iter_strings(item, key_hint=key_hint))
    return found


def safety_floor(tool_id: str, arguments: Mapping[str, Any] | str | None) -> str | None:
    """Deterministic hard safety floor blocking destructive deletions and unsafe shell syntax.

    Returns a non-empty violation code/message if blocked, or None if clean.
    """
    tool_low = tool_id.strip().lower()
    is_shell_tool = any(tok in tool_low for tok in _SHELL_TOOL_HINTS)

    if isinstance(arguments, str):
        pairs = [("command" if is_shell_tool else "", arguments)]
    elif isinstance(arguments, Mapping):
        pairs = _iter_strings(arguments)
    else:
        pairs = []

    shell_step_budget: list[int] = [0]
    shell_char_budget: list[int] = [0]
    ast_step_budget: list[int] = [0]
    seen_texts: set[str] = set()

    for arg_key, text in pairs:
        stripped = text.strip()
        if not stripped:
            continue

        deobf_stripped = _deobfuscate_shell(stripped)
        top_candidates = (stripped,) if deobf_stripped == stripped else (stripped, deobf_stripped)
        for candidate in top_candidates:
            if candidate in seen_texts:
                continue
            seen_texts.add(candidate)
            violation = _check_text_against_safety_patterns(
                candidate,
                _step_budget=shell_step_budget,
                _ast_step_budget=ast_step_budget,
                _char_budget=shell_char_budget,
                _seen_texts=seen_texts,
            )
            if violation is not None:
                return violation

        is_cmd_field = is_shell_tool or arg_key in _SHELL_ARG_KEYS
        pre_split_tokens: list[str] | None = None
        if is_cmd_field:
            if re.search(r"[<>]\(", stripped) or (
                deobf_stripped != stripped and re.search(r"[<>]\(", deobf_stripped)
            ):
                return "safety_floor:shell_process_substitution"
            try:
                parse_target = (
                    _strip_shell_line_continuations(stripped) if "\\\n" in stripped else stripped
                )
                if "$'" in parse_target:
                    parse_target = _normalize_ansi_c_quotes(parse_target)
                if '$"' in parse_target:
                    parse_target = _normalize_locale_dquotes(parse_target)
                pre_split_tokens = _posix_shlex_split(parse_target)
            except ValueError as exc:
                return f"safety_floor:unparseable_shell_syntax ({exc})"

        embedded = _extract_embedded_strings(stripped, pre_split_tokens=pre_split_tokens)
        if deobf_stripped != stripped:
            seen_emb = set(embedded)
            for item in _extract_embedded_strings(deobf_stripped):
                if item not in seen_emb:
                    seen_emb.add(item)
                    embedded.append(item)
        for emb in embedded:
            deobf_emb = _deobfuscate_shell(emb)
            emb_candidates = (emb,) if deobf_emb == emb else (emb, deobf_emb)
            for candidate in emb_candidates:
                if candidate in seen_texts:
                    continue
                seen_texts.add(candidate)
                violation = _check_text_against_safety_patterns(
                    candidate,
                    _step_budget=shell_step_budget,
                    _ast_step_budget=ast_step_budget,
                    _char_budget=shell_char_budget,
                    _seen_texts=seen_texts,
                )
                if violation is not None:
                    return violation

    return None


def sanitize_audit_arguments(value: Any, *, key_name: str = "") -> Any:
    """Redact secrets in audit logs using ONLY length and SHA-256 prefix (never raw secrets)."""
    if isinstance(value, Mapping):
        return {str(k): sanitize_audit_arguments(v, key_name=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_audit_arguments(item, key_name=key_name) for item in value]
    if isinstance(value, tuple):
        return [sanitize_audit_arguments(item, key_name=key_name) for item in value]
    if isinstance(value, str):
        if (
            (key_name and is_sensitive_key_strict(key_name))
            or contains_unredacted_secret_strict(value)
            or _RAW_SECRET_TOKEN_RE.search(value) is not None
        ):
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
            return {
                "redacted": True,
                "length": len(value),
                "sha256_prefix": digest,
            }
        return value
    if key_name and is_sensitive_key_strict(key_name) and value is not None:
        raw_repr = str(value)
        digest = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()[:8]
        return {
            "redacted": True,
            "length": len(raw_repr),
            "sha256_prefix": digest,
        }
    return value


class PolicyRule(FrozenModel):
    """Single deterministic authorization rule inside a PolicySet."""

    rule_id: NonEmptyStr
    effect: Literal["allow", "deny"]
    action_pattern: NonEmptyStr
    lanes: tuple[Lane, ...] = ()
    roles: tuple[NonEmptyStr, ...] = ()
    resource_acl: dict[str, Literal["allow", "deny"]] = Field(default_factory=dict)
    max_risk: Literal["read", "write", "admin"] = "read"


class PolicySet(FrozenModel):
    """Versioned policy bundle evaluated fail-closed by PolicyGateway."""

    policy_version: NonEmptyStr
    rules: tuple[PolicyRule, ...] = ()
    default_effect: Literal["deny"] = "deny"
    document_acls: dict[str, dict[str, Literal["allow", "deny"]]] = Field(default_factory=dict)


class PolicyRequest(FrozenModel):
    """Input envelope describing a requested tool or resource action."""

    actor_id: NonEmptyStr
    actor_role: NonEmptyStr
    lane: Lane
    tool_id: NonEmptyStr
    action_kind: Literal["read", "write", "unknown_mcp"] | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    resource_id: str | None = None
    session_id: str | None = None
    target_origin: HttpOrigin | None = None
    task_id: str | None = None
    run_id: str | None = None
    step_id: str | None = None
    is_mcp_tool: bool = False
    mcp_known_read_only: bool = False
    permit_token: str | None = None


class ExecutionPermit(FrozenModel):
    """Single-use, exact-argument, takeover-epoch-bound execution permit."""

    permit_id: NonEmptyStr
    tool_id: NonEmptyStr
    canonical_args_hash: NonEmptyStr
    actor_id: NonEmptyStr
    session_key: NonEmptyStr
    takeover_epoch: int = Field(ge=0)
    expires_at: UtcDatetime
    consumed: bool = False


class PolicyDecision(FrozenModel):
    """Audited authorization verdict emitted by PolicyGateway."""

    allowed: bool
    decision: Literal["allow", "deny"]
    reason: NonEmptyStr
    matched_rule_ids: tuple[str, ...] = ()
    canonical_args_hash: NonEmptyStr
    effective_action_kind: Literal["read", "write"]
    idempotency_key: NonEmptyStr
    audit_recorded: bool = False
    receipt_recorded: bool = False
    safety_violation: str | None = None


class PolicyGateway:
    """Central Decide -> Record -> Act policy gate enforcing fail-closed governance."""

    def __init__(
        self,
        policy_set: PolicySet | None = None,
        *,
        audit_sink: AuditSink | None = None,
        receipt_sink: ReceiptSink | None = None,
        require_audit_sink: bool = True,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._policy_set = policy_set
        self._audit_sink = audit_sink
        self._receipt_sink = receipt_sink
        self._require_audit_sink = require_audit_sink
        self._clock = clock
        self._lock = threading.Lock()
        self._permits: dict[str, ExecutionPermit] = {}
        self._takeover_epochs: dict[str, int] = {}

    @property
    def policy_set(self) -> PolicySet | None:
        return self._policy_set

    def current_takeover_epoch(self, session_key: str = "default") -> int:
        with self._lock:
            return self._takeover_epochs.get(session_key, 0)

    def invalidate_takeover(self, session_key: str = "default") -> int:
        """Increment takeover epoch and invalidate all unconsumed permits for session_key."""
        with self._lock:
            next_epoch = self._takeover_epochs.get(session_key, 0) + 1
            self._takeover_epochs[session_key] = next_epoch
            for pid in list(self._permits.keys()):
                if self._permits[pid].session_key == session_key:
                    self._permits.pop(pid, None)
            return next_epoch

    def issue_permit(
        self,
        *,
        tool_id: str,
        arguments: Mapping[str, Any],
        actor_id: str,
        session_key: str = "default",
        ttl_seconds: float = 300.0,
    ) -> ExecutionPermit:
        """Issue a single-use exact-argument permit bound to current takeover epoch."""
        now = ensure_utc(self._clock())
        args_hash = canonical_json_hash(dict(arguments))
        permit_id = f"prm_{uuid.uuid4().hex[:16]}"
        with self._lock:
            epoch = self._takeover_epochs.get(session_key, 0)
            permit = ExecutionPermit(
                permit_id=permit_id,
                tool_id=tool_id,
                canonical_args_hash=args_hash,
                actor_id=actor_id,
                session_key=session_key,
                takeover_epoch=epoch,
                expires_at=now + timedelta(seconds=max(1.0, ttl_seconds)),
                consumed=False,
            )
            self._permits[permit_id] = permit
            return permit

    def _consume_permit(
        self,
        *,
        permit_token: str,
        tool_id: str,
        actor_id: str,
        session_key: str,
        args_hash: str,
        now: datetime,
    ) -> tuple[bool, str]:
        with self._lock:
            permit = self._permits.get(permit_token)
            if permit is None:
                return False, "permit_not_found_or_invalidated"
            if permit.consumed:
                return False, "permit_already_consumed"
            if now >= ensure_utc(permit.expires_at):
                self._permits.pop(permit_token, None)
                return False, "permit_expired"
            current_epoch = self._takeover_epochs.get(session_key, 0)
            if permit.takeover_epoch != current_epoch:
                self._permits.pop(permit_token, None)
                return False, "permit_invalidated_by_takeover"
            if permit.tool_id != tool_id or permit.actor_id != actor_id:
                return False, "permit_actor_or_tool_mismatch"
            if permit.canonical_args_hash != args_hash:
                return False, "permit_canonical_args_hash_mismatch"
            self._permits[permit_token] = permit.model_copy(update={"consumed": True})
            return True, "permit_valid"

    @staticmethod
    def _effective_action_kind(req: PolicyRequest) -> Literal["read", "write"]:
        if req.is_mcp_tool:
            if req.mcp_known_read_only and req.action_kind == "read":
                return "read"
            return "write"
        if req.action_kind in (None, "unknown_mcp", "write"):
            return "write"
        return "read"

    @staticmethod
    def _build_idempotency_key(req: PolicyRequest, args_hash: str) -> str:
        raw = f"{req.run_id or 'no-run'}:{req.step_id or 'no-step'}:{req.tool_id}:{args_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _evaluate_document_acl(self, req: PolicyRequest) -> Literal["allow", "deny", "none"]:
        assert self._policy_set is not None
        if not req.resource_id:
            return "none"
        acl = self._policy_set.document_acls.get(req.resource_id)
        if not acl:
            return "none"

        principal_keys = [req.actor_id, f"role:{req.actor_role}", req.actor_role, "*"]
        observed: set[Literal["allow", "deny"]] = set()
        for key in principal_keys:
            if key in acl:
                observed.add(acl[key])
        if "deny" in observed:
            return "deny"
        if len(observed) > 1:
            return "deny"
        if "allow" in observed:
            return "allow"
        return "deny"

    def _evaluate_core(
        self, req: PolicyRequest, *, consume_permit: bool
    ) -> tuple[bool, str, tuple[str, ...], str, Literal["read", "write"], str, str | None]:
        args_hash = canonical_json_hash(req.arguments)
        effective_kind = self._effective_action_kind(req)
        idem_key = self._build_idempotency_key(req, args_hash)
        now = ensure_utc(self._clock())

        # 1. Hard safety_floor overrides any rule
        violation = safety_floor(req.tool_id, req.arguments)
        if violation is not None:
            return False, violation, (), args_hash, effective_kind, idem_key, violation

        # 2. Missing/empty policy -> fail closed
        if self._policy_set is None or not self._policy_set.rules:
            return False, "missing_policy", (), args_hash, effective_kind, idem_key, None

        # 3. Document ACL (deny wins)
        doc_verdict = self._evaluate_document_acl(req)
        if doc_verdict == "deny":
            return False, "document_acl_deny", (), args_hash, effective_kind, idem_key, None

        # 4. Industrial lane write protection
        if req.lane == Lane.INDUSTRIAL and effective_kind == "write":
            return False, "industrial_read_only_lane", (), args_hash, effective_kind, idem_key, None

        # 5. Evaluate rules with broken-rule fail-closed protection
        matched_allow: list[str] = []
        matched_deny: list[str] = []
        required_risk_rank = _RISK_RANK[effective_kind]

        try:
            for rule in self._policy_set.rules:
                if rule.lanes and req.lane not in rule.lanes:
                    continue
                if rule.roles and req.actor_role not in rule.roles:
                    continue
                pattern = re.compile(rule.action_pattern)
                if pattern.fullmatch(req.tool_id) is None and pattern.search(req.tool_id) is None:
                    continue
                if req.resource_id and rule.resource_acl:
                    r_acl = rule.resource_acl.get(req.resource_id) or rule.resource_acl.get("*")
                    if r_acl == "deny":
                        matched_deny.append(rule.rule_id)
                        continue
                if rule.effect == "deny":
                    matched_deny.append(rule.rule_id)
                else:
                    if _RISK_RANK[rule.max_risk] < required_risk_rank:
                        continue
                    matched_allow.append(rule.rule_id)
        except Exception as exc:  # noqa: BLE001
            return (
                False,
                f"broken_policy_rule:{exc}",
                tuple(matched_deny + matched_allow),
                args_hash,
                effective_kind,
                idem_key,
                None,
            )

        if matched_deny:
            return (
                False,
                "explicit_rule_deny",
                tuple(matched_deny),
                args_hash,
                effective_kind,
                idem_key,
                None,
            )

        if not matched_allow:
            return (
                False,
                "default_deny_no_matching_allow_rule",
                (),
                args_hash,
                effective_kind,
                idem_key,
                None,
            )

        # 6. Validate & consume single-use exact-argument permit if supplied
        if req.permit_token is not None:
            session_key = req.session_id or "default"
            if consume_permit:
                ok, p_reason = self._consume_permit(
                    permit_token=req.permit_token,
                    tool_id=req.tool_id,
                    actor_id=req.actor_id,
                    session_key=session_key,
                    args_hash=args_hash,
                    now=now,
                )
            else:
                with self._lock:
                    permit = self._permits.get(req.permit_token)
                    current_epoch = self._takeover_epochs.get(session_key, 0)
                    if permit is None:
                        ok, p_reason = False, "permit_not_found_or_invalidated"
                    elif permit.consumed:
                        ok, p_reason = False, "permit_already_consumed"
                    elif now >= ensure_utc(permit.expires_at):
                        ok, p_reason = False, "permit_expired"
                    elif permit.takeover_epoch != current_epoch:
                        ok, p_reason = False, "permit_invalidated_by_takeover"
                    elif permit.tool_id != req.tool_id or permit.actor_id != req.actor_id:
                        ok, p_reason = False, "permit_actor_or_tool_mismatch"
                    elif permit.canonical_args_hash != args_hash:
                        ok, p_reason = False, "permit_canonical_args_hash_mismatch"
                    else:
                        ok, p_reason = True, "permit_valid"
            if not ok:
                return (
                    False,
                    p_reason,
                    tuple(matched_allow),
                    args_hash,
                    effective_kind,
                    idem_key,
                    None,
                )

        return (
            True,
            "allowed_by_policy",
            tuple(matched_allow),
            args_hash,
            effective_kind,
            idem_key,
            None,
        )

    def decide(self, req: PolicyRequest) -> PolicyDecision:
        """Pure non-mutating policy evaluation (for dry-run inspection)."""
        allowed, reason, matched, args_hash, eff_kind, idem_key, violation = self._evaluate_core(
            req, consume_permit=False
        )
        return PolicyDecision(
            allowed=allowed,
            decision="allow" if allowed else "deny",
            reason=reason,
            matched_rule_ids=matched,
            canonical_args_hash=args_hash,
            effective_action_kind=eff_kind,
            idempotency_key=idem_key,
            audit_recorded=False,
            receipt_recorded=False,
            safety_violation=violation,
        )

    def evaluate_and_record(
        self,
        req: PolicyRequest,
        *,
        require_receipt: bool = False,
    ) -> PolicyDecision:
        """Decide -> Record audit + optional in-flight receipt (fail-closed if recording fails)."""
        allowed, reason, matched, args_hash, eff_kind, idem_key, violation = self._evaluate_core(
            req, consume_permit=True
        )
        sanitized_args = sanitize_audit_arguments(req.arguments)
        audit_payload: dict[str, Any] = {
            "event_type": "policy_decision",
            "actor_id": req.actor_id,
            "actor_role": req.actor_role,
            "lane": req.lane.value,
            "tool_id": req.tool_id,
            "effective_action_kind": eff_kind,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "matched_rule_ids": list(matched),
            "canonical_args_hash": args_hash,
            "idempotency_key": idem_key,
            "resource_id": req.resource_id,
            "session_id": req.session_id,
            "task_id": req.task_id,
            "run_id": req.run_id,
            "step_id": req.step_id,
            "policy_version": self._policy_set.policy_version if self._policy_set else None,
            "arguments": sanitized_args,
            "recorded_at": ensure_utc(self._clock()).isoformat(),
        }

        audit_recorded = False
        if self._audit_sink is not None:
            try:
                self._audit_sink(audit_payload)
                audit_recorded = True
            except Exception as exc:  # noqa: BLE001
                allowed = False
                reason = f"audit_record_failed:{exc}"
        elif self._require_audit_sink:
            allowed = False
            reason = "missing_audit_sink"

        receipt_recorded = False
        if allowed and self._receipt_sink is not None:
            try:
                receipt_ok = bool(
                    self._receipt_sink(
                        req.run_id or "no-run",
                        req.step_id or "no-step",
                        idem_key,
                        {
                            "status": "in_flight",
                            "tool_id": req.tool_id,
                            "canonical_args_hash": args_hash,
                            "arguments": sanitized_args,
                        },
                    )
                )
                receipt_recorded = receipt_ok
                if not receipt_ok:
                    allowed = False
                    reason = "in_flight_receipt_rejected"
            except Exception as exc:  # noqa: BLE001
                allowed = False
                reason = f"in_flight_receipt_failed:{exc}"
        elif allowed and require_receipt:
            allowed = False
            reason = "missing_receipt_sink"

        return PolicyDecision(
            allowed=allowed,
            decision="allow" if allowed else "deny",
            reason=reason,
            matched_rule_ids=matched,
            canonical_args_hash=args_hash,
            effective_action_kind=eff_kind,
            idempotency_key=idem_key,
            audit_recorded=audit_recorded,
            receipt_recorded=receipt_recorded,
            safety_violation=violation,
        )

    @overload
    async def execute_gated(
        self,
        req: PolicyRequest,
        act_fn: Callable[[], Awaitable[T]],
        *,
        require_receipt: bool = False,
    ) -> tuple[PolicyDecision, T | None]: ...

    @overload
    async def execute_gated(
        self,
        req: PolicyRequest,
        act_fn: Callable[[], T],
        *,
        require_receipt: bool = False,
    ) -> tuple[PolicyDecision, T | None]: ...

    async def execute_gated(
        self,
        req: PolicyRequest,
        act_fn: Callable[[], Any],
        *,
        require_receipt: bool = False,
    ) -> tuple[PolicyDecision, Any]:
        """Enforce Decide -> Record -> Act so callers cannot execute before audit recording."""
        decision = self.evaluate_and_record(req, require_receipt=require_receipt)
        if not decision.allowed:
            return decision, None
        result = act_fn()
        if inspect.isawaitable(result):
            awaited = await result
            return decision, awaited
        return decision, result


def default_studio_policy_set(*, allow_general_writes: bool = False) -> PolicySet:
    """Built-in PolicySet for Studio turns (denies destructive ops, gates writes explicitly)."""
    rules: list[PolicyRule] = [
        PolicyRule(
            rule_id="allow_general_read",
            effect="allow",
            action_pattern=r".*",
            lanes=(Lane.GENERAL, Lane.MIXED),
            max_risk="read",
        ),
        PolicyRule(
            rule_id="allow_industrial_read",
            effect="allow",
            action_pattern=r".*",
            lanes=(Lane.INDUSTRIAL,),
            max_risk="read",
        ),
    ]
    if allow_general_writes:
        rules.append(
            PolicyRule(
                rule_id="allow_general_write",
                effect="allow",
                action_pattern=r".*",
                lanes=(Lane.GENERAL,),
                max_risk="write",
            )
        )
    return PolicySet(policy_version="2.0.0", rules=tuple(rules))


__all__ = [
    "AuditSink",
    "ExecutionPermit",
    "PolicyDecision",
    "PolicyGateway",
    "PolicyRequest",
    "PolicyRule",
    "PolicySet",
    "ReceiptSink",
    "default_studio_policy_set",
    "safety_floor",
    "sanitize_audit_arguments",
]
