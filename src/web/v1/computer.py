"""Live Computer Gateway: capability tokens, takeover lock, Teach-a-Task, files, and WS bridges."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import inspect
import json
import math
import mimetypes
import os
import secrets
import shutil
import signal
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse, Response

from src.storage.redaction import contains_unredacted_secret_strict, redact_payload_strict
from src.web.auth import verify_websocket_token
from src.web.live_browser import LiveBrowserController
from src.web.live_terminal import LiveTerminalSession
from src.web.protocols import maybe_await
from src.web.v1.rfb_gate import (
    DEFAULT_VNC_PASSWD_PATH,
    RfbHandshakeError,
    RfbInputGate,
    perform_backend_vnc_handshake,
    perform_client_none_handshake,
)
from src.web.workspace import (
    _has_git_segment,
    _is_sensitive_filename,
    _resolve_relative_project_path,
    default_projects_root,
    list_local_projects,
    list_project_files,
    read_project_file,
    resolve_project_dir,
)

ControlOwner = Literal["agent", "human_takeover", "disconnected", "reconnecting"]

_MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MiB
_MAX_CLIPBOARD_BYTES: int = 64 * 1024  # 64 KiB
_MAX_TEACH_STEPS: int = 200
_MAX_TEACH_DURATION_S: float = 600.0  # 10 minutes
_MAX_IDEMPOTENCY_KEYS: int = 512
_RAW_BROWSER_INPUT_TYPES: frozenset[str] = frozenset(
    {"click", "dblclick", "wheel", "type", "key"}
)
_NAV_BROWSER_TYPES: frozenset[str] = frozenset(
    {"start", "stop", "navigate", "back", "forward", "reload"}
)
_ALLOWED_SIGNALS: dict[str, int] = {
    "SIGINT": int(signal.SIGINT),
    "INT": int(signal.SIGINT),
    "SIGTERM": int(signal.SIGTERM),
    "TERM": int(signal.SIGTERM),
    "SIGTSTP": int(signal.SIGTSTP),
    "TSTP": int(signal.SIGTSTP),
    "SIGQUIT": int(signal.SIGQUIT),
    "QUIT": int(signal.SIGQUIT),
    "SIGHUP": int(signal.SIGHUP),
    "HUP": int(signal.SIGHUP),
}


class DuplicateIdempotencyKeyError(RuntimeError):
    """Raised when a mutating takeover request reuses an existing Idempotency-Key."""


def _utc_now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_to_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scrub(value: Any) -> Any:
    return redact_payload_strict(value)


def _scrub_str(value: str) -> str:
    scrubbed = str(redact_payload_strict(value))
    if contains_unredacted_secret_strict(scrubbed):
        return "[REDACTED]"
    return scrubbed


def coerce_finite_int(raw: Any) -> int:
    """Coerce a JSON scalar to a finite integer, rejecting bools and non-finite floats."""
    if isinstance(raw, bool):
        raise ValueError("Boolean is not a valid integer.")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        if not math.isfinite(raw):
            raise ValueError("Non-finite float cannot be converted to integer.")
        return int(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise ValueError("Empty string is not a valid integer.")
        return int(stripped)
    raise TypeError(f"Unsupported integer type: {type(raw).__name__}")


def _safe_coord_int(raw: Any, default: int = 0) -> int:
    if isinstance(raw, bool):
        return default
    try:
        val = float(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(val):
        return default
    return int(round(val))


def _to_json_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return dict(obj)
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="json")
        if isinstance(dumped, dict):
            return dict(dumped)
    return {}


async def _read_optional_json_object(request: Request) -> dict[str, Any]:
    raw_body = await request.body()
    if not raw_body.strip():
        return {}
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON request body.",
        ) from exc
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be a JSON object.",
        )
    return parsed


async def _emit_event_bus(
    event_bus: Any,
    event_type: str,
    payload: dict[str, Any],
    *,
    bot_id: str | None = None,
    thread_id: str | None = None,
    turn_id: str | None = None,
) -> None:
    """Publish a normalized SSE event to any compatible EventBus implementation."""
    if event_bus is None:
        return
    fn = getattr(event_bus, "publish", None) or getattr(event_bus, "emit", None)
    if not callable(fn):
        return

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        with contextlib.suppress(Exception):
            await maybe_await(fn(event_type, payload))
        return

    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    kwargs: dict[str, Any] = {}
    if has_var_kw or "bot_id" in params:
        kwargs["bot_id"] = bot_id
    if has_var_kw or "thread_id" in params:
        kwargs["thread_id"] = thread_id
    if has_var_kw or "turn_id" in params:
        kwargs["turn_id"] = turn_id

    if "event_type" in params and "payload" in params:
        kwargs["event_type"] = event_type
        kwargs["payload"] = payload
        await maybe_await(fn(**kwargs))
        return
    if "type" in params and "payload" in params:
        kwargs["type"] = event_type
        kwargs["payload"] = payload
        await maybe_await(fn(**kwargs))
        return

    positional = [
        p
        for p in params.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        await maybe_await(fn(event_type, payload, **kwargs))
    elif len(positional) == 1:
        envelope = {
            "type": event_type,
            "payload": payload,
            "bot_id": bot_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "ts": _utc_now_iso(),
        }
        await maybe_await(fn(envelope))


def _call_kwargs_for_signature(
    fn: Any,
    alias_map: dict[str, Any],
    canonical: dict[str, Any],
) -> dict[str, Any]:
    """Build keyword arguments matching a callable's signature cleanly."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return dict(canonical)

    params = sig.parameters
    matched: dict[str, Any] = {}
    has_var_kw = False
    for name, param in params.items():
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            has_var_kw = True
            continue
        if name in alias_map:
            matched[name] = alias_map[name]
    if has_var_kw:
        return {**canonical, **matched}
    return matched


async def _store_get_bot_info(
    store: Any,
    bot_id: str,
    fallback_thread_id: str,
) -> tuple[str, str]:
    """Look up a bot's display name and thread_id from store if available."""
    if store is None:
        return "Chief of Staff", fallback_thread_id
    getter = getattr(store, "get_bot", None)
    if not callable(getter):
        return "Chief of Staff", fallback_thread_id
    with contextlib.suppress(Exception):
        raw = await maybe_await(getter(bot_id))
        info = _to_json_dict(raw)
        if info:
            name = str(info.get("name") or "Chief of Staff")
            thread_id = str(info.get("thread_id") or fallback_thread_id)
            return name, thread_id
    return "Chief of Staff", fallback_thread_id


async def _store_create_skill(
    store: Any,
    *,
    bot_id: str,
    name: str,
    description: str,
    content_md: str,
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    now_iso = _utc_now_iso()
    fallback: dict[str, Any] = {
        "id": f"skl_{secrets.token_hex(6)}",
        "bot_id": bot_id,
        "name": name,
        "description": description,
        "content_md": content_md,
        "steps_count": len(steps),
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    if store is None:
        return fallback
    fn = getattr(store, "create_skill", None)
    if not callable(fn):
        return fallback
    alias_map: dict[str, Any] = {
        "bot_id": bot_id,
        "name": name,
        "title": name,
        "description": description,
        "summary": description,
        "content_md": content_md,
        "instructions": content_md,
        "markdown": content_md,
        "body": content_md,
        "content": content_md,
        "steps": steps,
        "source": "teach_a_task",
    }
    canonical: dict[str, Any] = {
        "bot_id": bot_id,
        "name": name,
        "description": description,
        "content_md": content_md,
        "source": "taught",
    }
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.keys())
    except (TypeError, ValueError):
        params = []
    if params == ["data"]:
        created = await maybe_await(fn(canonical))
    else:
        kwargs = _call_kwargs_for_signature(fn, alias_map, canonical)
        created = await maybe_await(fn(**kwargs))
    result = _to_json_dict(created)
    return result if result else fallback


async def _store_create_artifact(
    store: Any,
    *,
    bot_id: str,
    thread_id: str,
    title: str,
    content_md: str,
    message_id: str | None = None,
) -> dict[str, Any]:
    now_iso = _utc_now_iso()
    size_bytes = len(content_md.encode("utf-8"))
    fallback: dict[str, Any] = {
        "id": f"art_{secrets.token_hex(6)}",
        "bot_id": bot_id,
        "thread_id": thread_id,
        "message_id": message_id,
        "type": "skill",
        "title": title,
        "content_md": content_md,
        "url": None,
        "file_path": None,
        "mime_type": "text/markdown",
        "size_bytes": size_bytes,
        "pinned": False,
        "share_scope": "private",
        "version": 1,
        "superseded_by_id": None,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    if store is None:
        return fallback
    fn = getattr(store, "create_artifact", None)
    if not callable(fn):
        return fallback
    alias_map: dict[str, Any] = {
        "bot_id": bot_id,
        "thread_id": thread_id,
        "message_id": message_id,
        "type": "skill",
        "artifact_type": "skill",
        "title": title,
        "name": title,
        "content_md": content_md,
        "content": content_md,
        "mime_type": "text/markdown",
        "size_bytes": size_bytes,
        "share_scope": "private",
    }
    canonical: dict[str, Any] = {
        "bot_id": bot_id,
        "thread_id": thread_id,
        "message_id": message_id,
        "type": "skill",
        "title": title,
        "content_md": content_md,
        "mime_type": "text/markdown",
    }
    kwargs = _call_kwargs_for_signature(fn, alias_map, canonical)
    created = await maybe_await(fn(**kwargs))
    result = _to_json_dict(created)
    return result if result else fallback


async def _store_create_message(
    store: Any,
    *,
    bot_id: str,
    bot_name: str,
    thread_id: str,
    content: str,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    now_iso = _utc_now_iso()
    art_summary = {
        "id": str(artifact.get("id", "")),
        "type": str(artifact.get("type", "skill")),
        "title": str(artifact.get("title", "")),
        "version": int(artifact.get("version", 1)),
        "superseded_by_id": artifact.get("superseded_by_id"),
    }
    fallback: dict[str, Any] = {
        "id": f"msg_{secrets.token_hex(6)}",
        "thread_id": thread_id,
        "sender_type": "bot",
        "sender_bot_id": bot_id,
        "sender_name": bot_name,
        "content": content,
        "thinking_text": "",
        "reply_to_id": None,
        "mentions": [],
        "attachments": [],
        "tool_calls": [],
        "artifacts": [art_summary],
        "reactions": {},
        "memory_diffs": [],
        "conversation_id": None,
        "model_id": None,
        "status": "done",
        "created_at": now_iso,
    }
    if store is None:
        return fallback
    fn = (
        getattr(store, "create_message", None)
        or getattr(store, "add_message", None)
        or getattr(store, "append_message", None)
    )
    if not callable(fn):
        return fallback
    alias_map: dict[str, Any] = {
        "thread_id": thread_id,
        "sender_type": "bot",
        "sender_bot_id": bot_id,
        "bot_id": bot_id,
        "sender_name": bot_name,
        "content": content,
        "text": content,
        "artifacts": [art_summary],
        "status": "done",
    }
    canonical: dict[str, Any] = {
        "thread_id": thread_id,
        "sender_type": "bot",
        "sender_bot_id": bot_id,
        "sender_name": bot_name,
        "content": content,
        "artifacts": [art_summary],
        "status": "done",
    }
    kwargs = _call_kwargs_for_signature(fn, alias_map, canonical)
    created = await maybe_await(fn(**kwargs))
    result = _to_json_dict(created)
    return result if result else fallback


def _describe_browser_action(event: dict[str, Any], *, url: str = "") -> str:
    ev_type = str(event.get("type") or event.get("action") or "").strip().lower()
    if ev_type == "navigate":
        target = _scrub_str(str(event.get("url") or url or "").strip())
        return f"Navigate to {target}" if target else "Navigate browser"
    if ev_type == "start":
        target = _scrub_str(str(event.get("url") or url or "").strip())
        return f"Start browser at {target}" if target else "Start browser"
    if ev_type == "stop":
        return "Stop browser"
    if ev_type == "back":
        return "Go back in browser history"
    if ev_type == "forward":
        return "Go forward in browser history"
    if ev_type == "reload":
        return "Reload current page"
    if ev_type == "click":
        x = _safe_coord_int(event.get("x", 0))
        y = _safe_coord_int(event.get("y", 0))
        btn = str(event.get("button", "left")).lower()
        return f"Click ({btn}) at ({x}, {y})"
    if ev_type == "dblclick":
        x = _safe_coord_int(event.get("x", 0))
        y = _safe_coord_int(event.get("y", 0))
        return f"Double-click at ({x}, {y})"
    if ev_type == "wheel":
        dx = _safe_coord_int(event.get("dx", 0))
        dy = _safe_coord_int(event.get("dy", 0))
        return f"Scroll by ({dx}, {dy})"
    if ev_type == "type":
        raw_text = str(event.get("text", ""))
        scrubbed = _scrub_str(raw_text)
        preview = scrubbed[:60] + ("..." if len(scrubbed) > 60 else "")
        return f'Type "{preview}"'
    if ev_type == "key":
        key = _scrub_str(str(event.get("key", "")))
        return f'Press key "{key}"'
    return f"Perform action {ev_type or 'unknown'}"


def _compile_skill_markdown(name: str, steps: list[dict[str, Any]]) -> str:
    clean_name = _scrub_str(name.strip()) or "Recorded Workflow"
    lines: list[str] = [
        f"# Skill: {clean_name}",
        "",
        f"_Recorded via Teach-a-Task on {_utc_now_iso()} ({len(steps)} step(s))._",
        "",
        "## Steps",
    ]
    if not steps:
        lines.append("1. No interactive actions were captured during this recording session.")
    else:
        for step in steps:
            idx = int(step.get("step_index", 0))
            action = _scrub_str(str(step.get("action", "action")))
            desc = _scrub_str(str(step.get("description", "")))
            step_url = _scrub_str(str(step.get("url", "")).strip())
            url_suffix = f" (`{step_url}`)" if step_url else ""
            lines.append(f"{idx}. **{action}** — {desc}{url_suffix}")
    lines.extend(
        [
            "",
            "## Execution Notes",
            "- Replay steps in order while verifying expected page state after each transition.",
            "- Request operator approval before executing destructive or irreversible actions.",
        ]
    )
    return "\n".join(lines) + "\n"


async def _push_x11_clipboard(text: str) -> bool:
    """Push clipboard text onto DISPLAY=:1 via xclip or xsel without logging text."""
    encoded = text.encode("utf-8", errors="replace")[:_MAX_CLIPBOARD_BYTES]
    xclip = shutil.which("xclip")
    xsel = shutil.which("xsel")
    if xclip:
        cmd = [xclip, "-selection", "clipboard"]
    elif xsel:
        cmd = [xsel, "--clipboard", "--input"]
    else:
        return False

    env = os.environ.copy()
    env["DISPLAY"] = os.environ.get("GROKBOT_X11_DISPLAY", ":1")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        await asyncio.wait_for(proc.communicate(input=encoded), timeout=2.0)
    except (OSError, TimeoutError):
        return False
    return proc.returncode == 0


def _send_pty_signal(term: LiveTerminalSession, sig_name: str) -> bool:
    """Deliver a POSIX signal (e.g. SIGINT) to the PTY child process group."""
    normalized = sig_name.strip().upper()
    sig_num = _ALLOWED_SIGNALS.get(normalized)
    if sig_num is None:
        return False
    return term.send_signal(sig_num)


def _load_or_create_cap_secret(secret_path: Path) -> bytes:
    """Load or atomically create a 32-byte capability signing secret with 0600 permissions."""
    try:
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        if secret_path.is_file():
            raw = secret_path.read_bytes()
            with contextlib.suppress(OSError):
                os.chmod(secret_path, 0o600)
            if len(raw) == 32:
                return raw
            stripped = raw.strip()
            if len(stripped) >= 32:
                return stripped[:32]
            if stripped:
                return stripped

        new_secret = secrets.token_bytes(32)
        tmp_path = secret_path.with_name(
            f".grokbot_cap_secret.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, new_secret)
            finally:
                os.close(fd)
            try:
                os.link(tmp_path, secret_path)
            except FileExistsError:
                existing = secret_path.read_bytes()
                with contextlib.suppress(OSError):
                    os.chmod(secret_path, 0o600)
                if len(existing) == 32:
                    return existing
                stripped_existing = existing.strip()
                if stripped_existing:
                    return stripped_existing[:32]
                return new_secret
            with contextlib.suppress(OSError):
                os.chmod(secret_path, 0o600)
            return new_secret
        finally:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
    except OSError:
        return secrets.token_bytes(32)


@dataclass
class _VmState:
    vm_id: str
    control_owner: ControlOwner = "agent"
    lease_id: str | None = None
    lease_owner: str | None = None
    lease_expires_at: float | None = None
    idempotency_keys: dict[str, str] = field(default_factory=dict)
    active_url: str = ""
    active_tab_title: str = ""
    active_step_summary: str | None = None
    display_mode: str = "vnc"
    viewport_width: int = 1280
    viewport_height: int = 800
    is_teaching_task: bool = False
    teach_name: str | None = None
    teach_bot_id: str | None = None
    teach_thread_id: str | None = None
    teach_started_at: float | None = None
    teach_steps: list[dict[str, Any]] = field(default_factory=list)


class ComputerGateway:
    """Manages capability tokens, takeover locks, Teach-a-Task, and WS subscribers."""

    def __init__(
        self,
        *,
        vnc_host: str | None = None,
        vnc_port: int | None = None,
        vnc_passwd_path: Path | None = None,
        projects_root: Path | None = None,
        default_project: str = "Grokbotclon",
        cap_token_ttl_seconds: int = 60,
        lease_ttl_seconds: int = 90,
        signing_secret: bytes | None = None,
        screenshot_path: Path | None = None,
        store: Any = None,
        state_dir: Path | None = None,
        cap_secret_path: Path | None = None,
    ) -> None:
        self.vnc_host: str = (
            vnc_host
            if vnc_host is not None
            else (os.environ.get("GROKBOT_VNC_HOST", "").strip() or "127.0.0.1")
        )
        if vnc_port is not None:
            self.vnc_port: int = int(vnc_port)
        else:
            raw_port = os.environ.get("GROKBOT_VNC_PORT", "").strip()
            self.vnc_port = int(raw_port) if raw_port.isdigit() else 5900

        if vnc_passwd_path is not None:
            self.vnc_passwd_path: Path = vnc_passwd_path
        else:
            env_pw = os.environ.get("GROKBOT_VNC_PASSWD_PATH", "").strip()
            self.vnc_passwd_path = (
                Path(env_pw).expanduser() if env_pw else DEFAULT_VNC_PASSWD_PATH
            )

        self.projects_root: Path = (
            projects_root if projects_root is not None else default_projects_root()
        )
        self.default_project: str = default_project
        self.cap_token_ttl_seconds: int = max(10, int(cap_token_ttl_seconds))
        self.lease_ttl_seconds: int = max(10, int(lease_ttl_seconds))
        self.screenshot_path: Path | None = screenshot_path
        self._store: Any = store

        if signing_secret is not None:
            self._signing_secret: bytes = signing_secret
        else:
            env_secret = os.environ.get("GROKBOT_CAP_SECRET", "").strip()
            if env_secret:
                self._signing_secret = env_secret.encode("utf-8")
            else:
                resolved_secret_path = cap_secret_path
                if resolved_secret_path is None:
                    if state_dir is not None:
                        resolved_secret_path = state_dir / ".grokbot_cap_secret"
                    elif getattr(store, "db_path", None) is not None:
                        resolved_secret_path = Path(store.db_path).parent / ".grokbot_cap_secret"
                    else:
                        resolved_secret_path = Path("var") / ".grokbot_cap_secret"
                self._signing_secret = _load_or_create_cap_secret(resolved_secret_path)

        self._vms: dict[str, _VmState] = {}
        self._control_sockets: dict[str, set[WebSocket]] = {}

    def attach_store(self, store: Any) -> None:
        """Attach an optional WorkspaceStore for persistent VM/teach state."""
        if self._store is None and store is not None:
            self._store = store

    def _serialize_vm(self, vm: _VmState) -> dict[str, Any]:
        return {
            "vm_id": vm.vm_id,
            "control_owner": vm.control_owner,
            "lease_id": vm.lease_id,
            "lease_owner": vm.lease_owner,
            "lease_expires_at": vm.lease_expires_at,
            "idempotency_keys": dict(vm.idempotency_keys),
            "active_url": vm.active_url,
            "active_tab_title": vm.active_tab_title,
            "active_step_summary": vm.active_step_summary,
            "display_mode": vm.display_mode,
            "viewport_width": vm.viewport_width,
            "viewport_height": vm.viewport_height,
            "is_teaching_task": vm.is_teaching_task,
            "teach_name": vm.teach_name,
            "teach_bot_id": vm.teach_bot_id,
            "teach_thread_id": vm.teach_thread_id,
            "teach_started_at": vm.teach_started_at,
            "teach_steps": [dict(step) for step in vm.teach_steps],
        }

    def _load_vm_from_store(self, vm_id: str) -> _VmState | None:
        store = self._store
        if store is None:
            return None
        getter = getattr(store, "get_computer_vm", None) or getattr(store, "load_computer_vm", None)
        if not callable(getter):
            return None
        raw_vm: Any = None
        with contextlib.suppress(Exception):
            raw_vm = getter(vm_id)
        if not isinstance(raw_vm, dict):
            return None

        owner_raw = str(raw_vm.get("control_owner") or "agent")
        valid_owners: set[str] = {"agent", "human_takeover", "disconnected", "reconnecting"}
        control_owner: ControlOwner = (
            owner_raw if owner_raw in valid_owners else "agent"  # type: ignore[assignment]
        )
        raw_idem = raw_vm.get("idempotency_keys")
        idem_keys: dict[str, str] = (
            {str(k): str(v) for k, v in raw_idem.items()} if isinstance(raw_idem, dict) else {}
        )
        raw_steps = raw_vm.get("teach_steps")
        steps: list[dict[str, Any]] = (
            [dict(s) for s in raw_steps if isinstance(s, dict)]
            if isinstance(raw_steps, list)
            else []
        )

        list_steps_fn = getattr(store, "list_teach_steps", None) or getattr(
            store, "get_teach_steps", None
        )
        if callable(list_steps_fn):
            with contextlib.suppress(Exception):
                loaded_steps = list_steps_fn(vm_id)
                if isinstance(loaded_steps, list):
                    steps = [dict(s) for s in loaded_steps if isinstance(s, dict)]

        raw_exp = raw_vm.get("lease_expires_at")
        lease_exp: float | None = float(raw_exp) if isinstance(raw_exp, (int, float)) else None
        raw_started = raw_vm.get("teach_started_at")
        teach_started: float | None = (
            float(raw_started) if isinstance(raw_started, (int, float)) else None
        )
        vm = _VmState(
            vm_id=vm_id,
            control_owner=control_owner,
            lease_id=str(raw_vm["lease_id"]) if raw_vm.get("lease_id") is not None else None,
            lease_owner=(
                str(raw_vm["lease_owner"]) if raw_vm.get("lease_owner") is not None else None
            ),
            lease_expires_at=lease_exp,
            idempotency_keys=idem_keys,
            active_url=str(raw_vm.get("active_url") or ""),
            active_tab_title=str(raw_vm.get("active_tab_title") or ""),
            active_step_summary=(
                str(raw_vm["active_step_summary"])
                if raw_vm.get("active_step_summary") is not None
                else None
            ),
            display_mode=str(raw_vm.get("display_mode") or "vnc"),
            viewport_width=int(raw_vm.get("viewport_width") or 1280),
            viewport_height=int(raw_vm.get("viewport_height") or 800),
            is_teaching_task=bool(raw_vm.get("is_teaching_task", False)),
            teach_name=str(raw_vm["teach_name"]) if raw_vm.get("teach_name") is not None else None,
            teach_bot_id=(
                str(raw_vm["teach_bot_id"]) if raw_vm.get("teach_bot_id") is not None else None
            ),
            teach_thread_id=(
                str(raw_vm["teach_thread_id"])
                if raw_vm.get("teach_thread_id") is not None
                else None
            ),
            teach_started_at=teach_started,
            teach_steps=steps,
        )
        self._refresh_lease(vm)
        return vm

    def _persist_vm(self, vm: _VmState) -> None:
        store = self._store
        if store is None:
            return
        fn = getattr(store, "upsert_computer_vm", None) or getattr(
            store, "save_computer_vm", None
        )
        if not callable(fn):
            return
        vm_dict = self._serialize_vm(vm)
        with contextlib.suppress(Exception):
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if len(params) == 1 and params[0].kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                fn(vm_dict)
            elif (
                len(params) == 2
                and params[0].name == "vm_id"
                and params[1].name in {"state", "data", "payload", "vm"}
            ):
                fn(vm.vm_id, vm_dict)
            else:
                kwargs = _call_kwargs_for_signature(fn, vm_dict, vm_dict)
                fn(**kwargs)

    def _persist_teach_step(
        self,
        vm_id: str,
        step: dict[str, Any],
        vm_steps: list[dict[str, Any]] | None = None,
    ) -> None:
        store = self._store
        if store is None:
            return
        fn = (
            getattr(store, "append_teach_step", None)
            or getattr(store, "add_teach_step", None)
            or getattr(store, "record_teach_step", None)
        )
        if callable(fn):
            with contextlib.suppress(Exception):
                sig = inspect.signature(fn)
                params = list(sig.parameters.values())
                if (
                    len(params) == 2
                    and params[0].name == "vm_id"
                    and params[1].name in {"step", "data", "payload"}
                ):
                    fn(vm_id, step)
                else:
                    alias_map = {"vm_id": vm_id, **step}
                    kwargs = _call_kwargs_for_signature(fn, alias_map, alias_map)
                    fn(**kwargs)
        elif hasattr(store, "save_teach_steps"):
            save_fn = getattr(store, "save_teach_steps", None)
            if callable(save_fn):
                steps_to_save = (
                    [dict(s) for s in vm_steps]
                    if vm_steps is not None
                    else [dict(s) for s in self._get_vm(vm_id).teach_steps]
                )
                with contextlib.suppress(Exception):
                    save_fn(vm_id, steps_to_save)

    def _clear_teach_steps(self, vm_id: str) -> None:
        store = self._store
        if store is None:
            return
        fn = getattr(store, "clear_teach_steps", None) or getattr(
            store, "delete_teach_steps", None
        )
        if callable(fn):
            with contextlib.suppress(Exception):
                fn(vm_id)
        elif hasattr(store, "save_teach_steps"):
            save_fn = getattr(store, "save_teach_steps", None)
            if callable(save_fn):
                with contextlib.suppress(Exception):
                    save_fn(vm_id, [])

    def _get_vm(self, vm_id: str) -> _VmState:
        key = vm_id.strip() or "default"
        vm = self._vms.get(key)
        if vm is None:
            loaded = self._load_vm_from_store(key)
            vm = loaded if loaded is not None else _VmState(vm_id=key)
            self._vms[key] = vm
        return vm

    def _refresh_lease(self, vm: _VmState) -> str | None:
        """Expire a human takeover lease if its TTL has elapsed; returns expired lease_id."""
        if (
            vm.control_owner == "human_takeover"
            and vm.lease_expires_at is not None
            and time.time() >= vm.lease_expires_at
        ):
            expired_id = vm.lease_id
            vm.control_owner = "agent"
            vm.lease_id = None
            vm.lease_owner = None
            vm.lease_expires_at = None
            self._persist_vm(vm)
            return expired_id
        return None

    # ------------------------------------------------------------------
    # Capability Tokens (HMAC-SHA256)
    # ------------------------------------------------------------------

    def mint_cap_token(self, vm_id: str, *, ttl_seconds: int | None = None) -> str:
        """Mint a short-lived HMAC-SHA256 capability token scoped to `vm_id`."""
        ttl = self.cap_token_ttl_seconds if ttl_seconds is None else max(5, min(600, ttl_seconds))
        exp = time.time() + float(ttl)
        payload = {
            "vm_id": vm_id.strip() or "default",
            "exp": exp,
            "nonce": secrets.token_urlsafe(8),
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        sig = hmac.new(
            self._signing_secret,
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
        return f"{payload_b64}.{sig_b64}"

    def verify_cap_token(self, vm_id: str, token: str | None) -> bool:
        """Verify an HMAC-SHA256 capability token matches `vm_id` and is unexpired."""
        if not token or "." not in token:
            return False
        parts = token.split(".", 1)
        if len(parts) != 2:
            return False
        payload_b64, provided_sig = parts
        expected_sig_raw = hmac.new(
            self._signing_secret,
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        expected_sig = base64.urlsafe_b64encode(expected_sig_raw).decode("ascii").rstrip("=")
        if not hmac.compare_digest(provided_sig, expected_sig):
            return False

        padding = "=" * (-len(payload_b64) % 4)
        try:
            decoded = base64.urlsafe_b64decode((payload_b64 + padding).encode("ascii"))
            data = json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        expected_vm = vm_id.strip() or "default"
        if str(data.get("vm_id", "")) != expected_vm:
            return False
        try:
            exp = float(data.get("exp", 0.0))
        except (TypeError, ValueError):
            return False
        return time.time() < exp

    def mint_token_response(
        self,
        vm_id: str,
        *,
        ttl_seconds: int | None = None,
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Mint a capability token and return the full vnc-token endpoint payload."""
        clean_vm = vm_id.strip() or "default"
        clean_sess = session_id.strip() or "default"
        ttl = self.cap_token_ttl_seconds if ttl_seconds is None else max(5, min(600, ttl_seconds))
        expires_ts = time.time() + float(ttl)
        token = self.mint_cap_token(clean_vm, ttl_seconds=ttl)
        return {
            "cap_token": token,
            "expires_at": _ts_to_iso(expires_ts),
            "ttl_seconds": ttl,
            "ws_vnc_url": f"/ws/v1/computers/{clean_vm}/vnc?cap_token={token}",
            "ws_screencast_url": f"/ws/v1/computers/{clean_vm}/screencast?cap_token={token}",
            "ws_control_url": f"/ws/v1/computers/{clean_vm}/control?cap_token={token}",
            "ws_pty_url": f"/ws/v1/computers/{clean_vm}/pty/{clean_sess}?cap_token={token}",
        }

    # ------------------------------------------------------------------
    # Control Lock & VNC Probe
    # ------------------------------------------------------------------

    def get_control_owner(self, vm_id: str) -> ControlOwner:
        """Return current control owner for `vm_id`, expiring stale human leases cleanly."""
        vm = self._get_vm(vm_id)
        self._refresh_lease(vm)
        return vm.control_owner

    def is_human_takeover(self, vm_id: str) -> bool:
        """Return True iff human takeover is currently active and unexpired."""
        return self.get_control_owner(vm_id) == "human_takeover"

    def takeover(
        self,
        vm_id: str,
        *,
        owner: str = "operator",
        idempotency_key: str | None = None,
        ttl_seconds: int | None = None,
    ) -> _VmState:
        """Acquire or renew the exclusive human takeover lock for `vm_id`."""
        vm = self._get_vm(vm_id)
        self._refresh_lease(vm)

        clean_key = idempotency_key.strip() if idempotency_key else ""
        if clean_key:
            if clean_key in vm.idempotency_keys:
                raise DuplicateIdempotencyKeyError(
                    f"Duplicate Idempotency-Key {clean_key!r} for takeover on {vm.vm_id}."
                )
            if len(vm.idempotency_keys) >= _MAX_IDEMPOTENCY_KEYS:
                oldest = next(iter(vm.idempotency_keys))
                del vm.idempotency_keys[oldest]

        ttl = self.lease_ttl_seconds if ttl_seconds is None else max(10, min(600, ttl_seconds))
        lease_id = f"lse_{secrets.token_hex(8)}"
        vm.control_owner = "human_takeover"
        vm.lease_id = lease_id
        vm.lease_owner = owner.strip() or "operator"
        vm.lease_expires_at = time.time() + float(ttl)
        if clean_key:
            vm.idempotency_keys[clean_key] = lease_id
        self._persist_vm(vm)
        return vm

    def handback(self, vm_id: str) -> str | None:
        """Release human takeover back to the agent and return any previous lease_id."""
        vm = self._get_vm(vm_id)
        prev_lease = vm.lease_id
        vm.control_owner = "agent"
        vm.lease_id = None
        vm.lease_owner = None
        vm.lease_expires_at = None
        self._persist_vm(vm)
        return prev_lease

    def renew_lease(
        self,
        vm_id: str,
        *,
        lease_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """Renew an active human takeover lease; returns (ok, lease_id, lease_expires_at_iso)."""
        vm = self._get_vm(vm_id)
        self._refresh_lease(vm)
        if vm.control_owner != "human_takeover" or vm.lease_id is None:
            return False, None, None
        if lease_id and lease_id != vm.lease_id:
            return False, vm.lease_id, _ts_to_iso(vm.lease_expires_at)
        ttl = self.lease_ttl_seconds if ttl_seconds is None else max(10, min(600, ttl_seconds))
        vm.lease_expires_at = time.time() + float(ttl)
        self._persist_vm(vm)
        return True, vm.lease_id, _ts_to_iso(vm.lease_expires_at)

    def set_viewport(self, vm_id: str, *, width: int, height: int) -> tuple[int, int]:
        vm = self._get_vm(vm_id)
        vm.viewport_width = max(320, min(3840, int(width)))
        vm.viewport_height = max(240, min(2160, int(height)))
        self._persist_vm(vm)
        return vm.viewport_width, vm.viewport_height

    def _is_local_port_listening_procfs(self) -> bool | None:
        """Check Linux /proc/net/tcp* for a LISTEN socket without opening a TCP connection.

        Avoids triggering TigerVNC's BlacklistThreshold on repeated status polls.
        Returns None if procfs is unavailable or vnc_host is not loopback.
        """
        if self.vnc_host not in {"127.0.0.1", "localhost", "::1"}:
            return None
        port_hex = f":{self.vnc_port:04X}"
        found_proc = False
        for proc_file in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            if not proc_file.is_file():
                continue
            found_proc = True
            with contextlib.suppress(OSError):
                for line in proc_file.read_text(encoding="ascii", errors="ignore").splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "0A" and parts[1].upper().endswith(port_hex):
                        return True
        return False if found_proc else None

    async def is_vnc_available(self, *, timeout_s: float = 0.3) -> bool:
        """Check whether the VNC server is listening without triggering VNC auth blacklists."""
        procfs_res = self._is_local_port_listening_procfs()
        if procfs_res is not None:
            return procfs_res
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.vnc_host, self.vnc_port),
                timeout=timeout_s,
            )
        except (OSError, TimeoutError):
            return False
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True

    # ------------------------------------------------------------------
    # Teach-a-Task Recording
    # ------------------------------------------------------------------

    def is_teaching(self, vm_id: str) -> bool:
        vm = self._get_vm(vm_id)
        if not vm.is_teaching_task:
            return False
        if (
            vm.teach_started_at is not None
            and (time.time() - vm.teach_started_at) > _MAX_TEACH_DURATION_S
        ):
            return False
        return len(vm.teach_steps) < _MAX_TEACH_STEPS

    def start_teach(
        self,
        vm_id: str,
        *,
        name: str | None = None,
        bot_id: str | None = None,
        thread_id: str | None = None,
    ) -> _VmState:
        vm = self._get_vm(vm_id)
        clean_bot = (bot_id or "").strip() or "bot_chief"
        clean_thread = (thread_id or "").strip() or f"thr_{clean_bot}"
        clean_name = (name or "").strip() or "Recorded Workflow"
        vm.is_teaching_task = True
        vm.teach_name = _scrub_str(clean_name)[:120]
        vm.teach_bot_id = clean_bot
        vm.teach_thread_id = clean_thread
        vm.teach_started_at = time.time()
        vm.teach_steps = []
        self._clear_teach_steps(vm.vm_id)
        self._persist_vm(vm)
        return vm

    def record_teach_step(
        self,
        vm_id: str,
        *,
        action: str,
        description: str,
        url: str = "",
    ) -> dict[str, Any] | None:
        vm = self._get_vm(vm_id)
        if not self.is_teaching(vm_id):
            return None
        step: dict[str, Any] = {
            "step_index": len(vm.teach_steps) + 1,
            "action": _scrub_str(action)[:40],
            "description": _scrub_str(description)[:240],
            "url": _scrub_str(url)[:500],
            "ts": _utc_now_iso(),
        }
        vm.teach_steps.append(step)
        self._persist_teach_step(
            vm.vm_id,
            dict(step),
            vm_steps=[dict(s) for s in vm.teach_steps],
        )
        self._persist_vm(vm)
        return dict(step)

    def stop_teach(self, vm_id: str) -> tuple[str, str, str, list[dict[str, Any]]]:
        vm = self._get_vm(vm_id)
        name = vm.teach_name or "Recorded Workflow"
        bot_id = vm.teach_bot_id or "bot_chief"
        thread_id = vm.teach_thread_id or f"thr_{bot_id}"
        steps = [dict(step) for step in vm.teach_steps]
        vm.is_teaching_task = False
        vm.teach_name = None
        vm.teach_bot_id = None
        vm.teach_thread_id = None
        vm.teach_started_at = None
        vm.teach_steps = []
        self._clear_teach_steps(vm.vm_id)
        self._persist_vm(vm)
        return name, bot_id, thread_id, steps

    # ------------------------------------------------------------------
    # Browser Metadata & Status Snapshot
    # ------------------------------------------------------------------

    def update_browser_metadata(
        self,
        vm_id: str,
        *,
        url: str | None = None,
        title: str | None = None,
        step_summary: str | None = None,
    ) -> bool:
        vm = self._get_vm(vm_id)
        changed = False
        if url is not None:
            clean_url = _scrub_str(url)
            if clean_url != vm.active_url:
                vm.active_url = clean_url
                changed = True
        if title is not None:
            clean_title = _scrub_str(title)
            if clean_title != vm.active_tab_title:
                vm.active_tab_title = clean_title
                changed = True
        if step_summary is not None:
            vm.active_step_summary = _scrub_str(step_summary)[:160]
        if changed or step_summary is not None:
            self._persist_vm(vm)
        return changed

    async def get_status(
        self,
        vm_id: str,
        *,
        live_browser: LiveBrowserController | None = None,
    ) -> dict[str, Any]:
        """Build the contract-compliant ComputerStatus JSON payload for `vm_id`."""
        vm = self._get_vm(vm_id)
        self._refresh_lease(vm)
        vnc_available = await self.is_vnc_available()

        browser_running = False
        if live_browser is not None:
            with contextlib.suppress(Exception):
                b_st = await live_browser.status()
                browser_running = bool(b_st.get("running", False))
                if browser_running:
                    vm.active_url = _scrub_str(str(b_st.get("url", "")))
                    vm.active_tab_title = _scrub_str(str(b_st.get("title", "")))

        display_mode = "vnc" if vnc_available else "browser"
        vm.display_mode = display_mode
        comp_status = (
            vm.control_owner
            if vm.control_owner in {"disconnected", "reconnecting"}
            else "ready"
        )
        return {
            "vm_id": vm.vm_id,
            "status": comp_status,
            "control_owner": vm.control_owner,
            "lease_id": vm.lease_id,
            "lease_expires_at": _ts_to_iso(vm.lease_expires_at),
            "vnc_available": vnc_available,
            "browser_running": browser_running,
            "active_url": vm.active_url,
            "active_tab_title": vm.active_tab_title,
            "active_step_summary": vm.active_step_summary,
            "is_teaching_task": vm.is_teaching_task,
            "teach_name": vm.teach_name,
            "teach_steps_count": len(vm.teach_steps),
            "display_mode": display_mode,
        }

    # ------------------------------------------------------------------
    # Control WebSocket Registry
    # ------------------------------------------------------------------

    def register_control_socket(self, vm_id: str, ws: WebSocket) -> None:
        key = vm_id.strip() or "default"
        sockets = self._control_sockets.setdefault(key, set())
        sockets.add(ws)

    def unregister_control_socket(self, vm_id: str, ws: WebSocket) -> None:
        key = vm_id.strip() or "default"
        sockets = self._control_sockets.get(key)
        if sockets is not None:
            sockets.discard(ws)
            if not sockets:
                self._control_sockets.pop(key, None)

    async def broadcast_control(self, vm_id: str, message: dict[str, Any]) -> None:
        """Broadcast a JSON control notification to all active control WebSockets for `vm_id`."""
        key = vm_id.strip() or "default"
        sockets = list(self._control_sockets.get(key, ()))
        if not sockets:
            return
        dead: list[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister_control_socket(key, ws)


def _resolve_project_name(gateway: ComputerGateway, project: str | None) -> str:
    cleaned = (project or "").strip()
    if cleaned:
        return cleaned
    if (gateway.projects_root / gateway.default_project).is_dir():
        return gateway.default_project
    projects = list_local_projects(gateway.projects_root)
    if projects:
        return str(projects[0]["name"])
    return gateway.default_project


def _file_access_error_code(msg: str, *, allow_not_found: bool = False) -> int:
    low_msg = msg.lower()
    if (
        "restricted" in low_msg
        or "forbidden" in low_msg
        or "escapes" in low_msg
        or "escaping" in low_msg
    ):
        return status.HTTP_403_FORBIDDEN
    if allow_not_found and "not found" in low_msg:
        return status.HTTP_404_NOT_FOUND
    return status.HTTP_400_BAD_REQUEST


def _validate_file_target(
    gateway: ComputerGateway,
    project: str | None,
    rel_path: str,
    *,
    allow_root: bool = False,
    follow_symlinks: bool = True,
) -> tuple[str, Path, Path]:
    project_name = _resolve_project_name(gateway, project)
    project_dir = resolve_project_dir(gateway.projects_root, project_name)
    try:
        resolved_root = project_dir.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Invalid or escaping path: {rel_path!r}") from exc
    cleaned_rel = rel_path.strip().lstrip("/")
    if not cleaned_rel and not allow_root:
        raise ValueError("path must not be empty.")
    target = _resolve_relative_project_path(
        project_dir,
        cleaned_rel,
        follow_symlinks=follow_symlinks,
    )
    try:
        is_root = target == resolved_root or (
            follow_symlinks and target.resolve() == resolved_root
        )
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Invalid or escaping path: {rel_path!r}") from exc
    if not allow_root and is_root:
        raise ValueError("Operation on project root is forbidden.")
    if cleaned_rel:
        rel_obj = Path(cleaned_rel)
        try:
            resolved_target = target.resolve()
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"Invalid or escaping path: {rel_path!r}") from exc
        if not resolved_target.is_relative_to(resolved_root):
            raise ValueError(f"Path escapes project root: {rel_path!r}")
        if _has_git_segment(rel_obj) or _has_git_segment(
            resolved_target.relative_to(resolved_root)
        ):
            raise ValueError("Access to .git metadata is restricted.")
        if (
            _is_sensitive_filename(target)
            or _is_sensitive_filename(rel_obj)
            or _is_sensitive_filename(resolved_target)
        ):
            raise ValueError(f"Access to sensitive file {target.name!r} is restricted.")
    return project_name, resolved_root, target


def _validate_single_filename(name: str) -> str:
    cleaned = name.strip()
    if (
        not cleaned
        or cleaned in {".", ".."}
        or "/" in cleaned
        or "\\" in cleaned
        or "\x00" in cleaned
    ):
        raise ValueError(f"Invalid filename: {name!r}")
    if _is_sensitive_filename(Path(cleaned)):
        raise ValueError(f"Upload of sensitive filename {cleaned!r} is restricted.")
    return cleaned


def _ws_authorized(gateway: ComputerGateway, websocket: WebSocket, vm_id: str) -> bool:
    """Authorize computer WebSocket via `cap_token` or valid configured web token."""
    cap_token = websocket.query_params.get("cap_token")
    if cap_token is not None:
        return gateway.verify_cap_token(vm_id, cap_token)
    configured_web_token = getattr(getattr(websocket.app, "state", None), "web_token", None)
    if isinstance(configured_web_token, str) and configured_web_token:
        return verify_websocket_token(websocket, configured_web_token)
    return False


def create_computer_router(
    gateway: ComputerGateway,
    live_browser: LiveBrowserController,
    store: Any = None,
    event_bus: Any = None,
) -> APIRouter:
    """Create the FastAPI APIRouter for all Live Computer REST and WebSocket endpoints."""
    gateway.attach_store(store)
    router = APIRouter()

    async def _publish_computer_state(vm_id: str) -> dict[str, Any]:
        st = await gateway.get_status(vm_id, live_browser=live_browser)
        await gateway.broadcast_control(vm_id, {"op": "computer.state", "status": st})
        await _emit_event_bus(event_bus, "computer.state", st)
        return st

    # ------------------------------------------------------------------
    # REST: Status, Capability Token, Takeover, Handback, Actions
    # ------------------------------------------------------------------

    @router.get("/api/v1/computers/{vm_id}/status")
    async def api_computer_status(vm_id: str) -> JSONResponse:
        st = await gateway.get_status(vm_id, live_browser=live_browser)
        return JSONResponse(status_code=status.HTTP_200_OK, content=st)

    @router.post("/api/v1/computers/{vm_id}/vnc-token")
    async def api_computer_vnc_token(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        raw_ttl = body.get("ttl_seconds")
        ttl_arg: int | None = None
        if raw_ttl is not None:
            try:
                ttl_arg = coerce_finite_int(raw_ttl)
            except (TypeError, ValueError, OverflowError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail="ttl_seconds must be a finite integer.",
                ) from exc
        session_id = str(body.get("session_id") or "default").strip() or "default"
        token_payload = gateway.mint_token_response(
            vm_id,
            ttl_seconds=ttl_arg,
            session_id=session_id,
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=token_payload)

    @router.post("/api/v1/computers/{vm_id}/takeover")
    async def api_computer_takeover(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        owner = str(body.get("owner") or "operator").strip() or "operator"
        raw_ttl = body.get("ttl_seconds")
        ttl_arg: int | None = None
        if raw_ttl is not None:
            try:
                ttl_arg = coerce_finite_int(raw_ttl)
            except (TypeError, ValueError, OverflowError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail="ttl_seconds must be a finite integer.",
                ) from exc
        idem_key = request.headers.get("idempotency-key")
        try:
            gateway.takeover(
                vm_id,
                owner=owner,
                idempotency_key=idem_key,
                ttl_seconds=ttl_arg,
            )
        except DuplicateIdempotencyKeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        st = await _publish_computer_state(vm_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=st)

    @router.post("/api/v1/computers/{vm_id}/handback")
    async def api_computer_handback(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        reason = _scrub_str(str(body.get("reason") or "human_handback"))
        prev_lease = gateway.handback(vm_id)
        await gateway.broadcast_control(
            vm_id,
            {
                "op": "lease.revoked",
                "vm_id": vm_id,
                "lease_id": prev_lease,
                "reason": reason,
            },
        )
        st = await _publish_computer_state(vm_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=st)

    @router.post("/api/v1/computers/{vm_id}/actions")
    async def api_computer_actions(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        if not body:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Action JSON object is required.",
            )
        actor = str(body.get("actor") or "human").strip().lower()
        if actor == "agent" and gateway.get_control_owner(vm_id) == "human_takeover":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Automation locked: human takeover is active.",
            )

        action_event = dict(body)
        if "type" not in action_event and "action" in action_event:
            action_event["type"] = action_event["action"]

        try:
            action_result = await live_browser.perform_action(
                action_event,
                screenshot_path=gateway.screenshot_path,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=_scrub_str(str(exc)),
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=_scrub_str(str(exc)),
            ) from exc

        browser_st = action_result.get("status")
        browser_status: dict[str, Any] = dict(browser_st) if isinstance(browser_st, dict) else {}
        url = str(browser_status.get("url", ""))
        title = str(browser_status.get("title", ""))
        ev_type = str(action_event.get("type", "")).strip().lower()
        desc = _describe_browser_action(action_event, url=url)

        tab_changed = gateway.update_browser_metadata(
            vm_id,
            url=url,
            title=title,
            step_summary=desc,
        )
        if actor != "agent" and gateway.is_teaching(vm_id):
            step = gateway.record_teach_step(
                vm_id,
                action=ev_type or "action",
                description=desc,
                url=url,
            )
            if step is not None:
                await gateway.broadcast_control(
                    vm_id,
                    {
                        "op": "teach.step_captured",
                        "vm_id": vm_id,
                        "step": step,
                        "teach_steps_count": step["step_index"],
                    },
                )
        if tab_changed:
            await gateway.broadcast_control(
                vm_id,
                {
                    "op": "browser.tab_changed",
                    "vm_id": vm_id,
                    "url": _scrub_str(url),
                    "title": _scrub_str(title),
                },
            )
        comp_status = await _publish_computer_state(vm_id)
        response_payload = {
            "status": comp_status,
            "browser_status": _scrub(browser_status),
            "context": _scrub(action_result.get("context")),
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content=response_payload)

    # ------------------------------------------------------------------
    # REST: Workspace File Explorer
    # ------------------------------------------------------------------

    @router.get("/api/v1/computers/{vm_id}/files")
    async def api_computer_files_list(
        vm_id: str,
        path: str = "",
        project: str = "",
    ) -> JSONResponse:
        del vm_id
        project_name = _resolve_project_name(gateway, project)
        try:
            listing = list_project_files(gateway.projects_root, project_name, path)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_scrub_str(str(exc)),
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=listing)

    @router.get("/api/v1/computers/{vm_id}/file")
    async def api_computer_file_read(
        vm_id: str,
        path: str = "",
        project: str = "",
    ) -> JSONResponse:
        del vm_id
        project_name = _resolve_project_name(gateway, project)
        try:
            file_data = read_project_file(gateway.projects_root, project_name, path)
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg, allow_not_found=True)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=file_data)

    @router.get("/api/v1/computers/{vm_id}/file/download")
    async def api_computer_file_download(
        vm_id: str,
        path: str = "",
        project: str = "",
    ) -> Response:
        del vm_id
        try:
            _, _, target = _validate_file_target(gateway, project, path)
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc
        if not target.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found.",
            )
        file_size = target.stat().st_size
        if file_size > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File exceeds 50 MB download limit.",
            )
        raw_bytes = target.read_bytes()
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        safe_name = target.name.replace('"', "").replace("\r", "").replace("\n", "")
        return Response(
            content=raw_bytes,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )

    @router.post("/api/v1/computers/{vm_id}/files/upload", status_code=status.HTTP_201_CREATED)
    async def api_computer_files_upload(
        vm_id: str,
        request: Request,
        path: str = "",
        name: str = "",
        project: str = "",
    ) -> JSONResponse:
        del vm_id
        try:
            safe_name = _validate_single_filename(name)
            _, resolved_root, parent_dir = _validate_file_target(
                gateway,
                project,
                path,
                allow_root=True,
            )
            rel_join = f"{path.strip().strip('/')}/{safe_name}" if path.strip() else safe_name
            _, _, target = _validate_file_target(gateway, project, rel_join)
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc

        if parent_dir.exists() and not parent_dir.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target upload path is not a directory.",
            )
        try:
            parent_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot prepare upload directory: {exc}",
            ) from exc
        if target.exists() and target.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target upload file path is a directory.",
            )
        total_bytes = 0
        try:
            with target.open("wb") as handle:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > _MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="Upload exceeds 50 MB limit.",
                        )
                    handle.write(chunk)
        except HTTPException:
            with contextlib.suppress(OSError):
                target.unlink()
            raise
        except OSError as exc:
            with contextlib.suppress(OSError):
                target.unlink()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to write uploaded file: {exc}",
            ) from exc

        rel_posix = target.resolve().relative_to(resolved_root).as_posix()
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"rel_path": rel_posix, "size_bytes": total_bytes},
        )

    @router.post("/api/v1/computers/{vm_id}/files/mkdir", status_code=status.HTTP_201_CREATED)
    async def api_computer_files_mkdir(vm_id: str, request: Request) -> JSONResponse:
        del vm_id
        body = await _read_optional_json_object(request)
        rel_path = str(body.get("path") or "")
        project = str(body.get("project") or "")
        try:
            _, resolved_root, target = _validate_file_target(gateway, project, rel_path)
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot create directory: {exc}",
            ) from exc
        rel_posix = target.resolve().relative_to(resolved_root).as_posix()
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"rel_path": rel_posix},
        )

    @router.post("/api/v1/computers/{vm_id}/files/write")
    async def api_computer_files_write(vm_id: str, request: Request) -> JSONResponse:
        del vm_id
        body = await _read_optional_json_object(request)
        rel_path = str(body.get("path") or "")
        project = str(body.get("project") or "")
        raw_content = body.get("content")
        if not isinstance(raw_content, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Field 'content' must be a string.",
            )
        try:
            _, resolved_root, target = _validate_file_target(gateway, project, rel_path)
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc

        encoded = raw_content.encode("utf-8")
        if len(encoded) > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File content exceeds 50 MB limit.",
            )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot write file: {exc}",
            ) from exc
        rel_posix = target.resolve().relative_to(resolved_root).as_posix()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"rel_path": rel_posix, "size_bytes": len(encoded)},
        )

    @router.delete("/api/v1/computers/{vm_id}/files")
    async def api_computer_files_delete(
        vm_id: str,
        path: str = "",
        project: str = "",
    ) -> JSONResponse:
        del vm_id
        try:
            _, resolved_root, target = _validate_file_target(
                gateway,
                project,
                path,
                follow_symlinks=False,
            )
        except ValueError as exc:
            msg = str(exc)
            code = _file_access_error_code(msg)
            raise HTTPException(status_code=code, detail=_scrub_str(msg)) from exc
        try:
            st = target.lstat()
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target path not found.",
            ) from exc
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot inspect path: {exc}",
            ) from exc

        try:
            resolved_target = target.resolve()
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Deletion outside project root is forbidden.",
            ) from exc
        if resolved_target == resolved_root or not resolved_target.is_relative_to(resolved_root):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Deletion outside project root is forbidden.",
            )
        try:
            if stat.S_ISLNK(st.st_mode):
                target.unlink()
            elif stat.S_ISDIR(st.st_mode):
                shutil.rmtree(target)
            else:
                target.unlink()
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete path: {exc}",
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content={"deleted": True})

    # ------------------------------------------------------------------
    # REST: Teach-a-Task Start & Stop
    # ------------------------------------------------------------------

    @router.post("/api/v1/computers/{vm_id}/teach/start")
    async def api_computer_teach_start(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        name = str(body.get("name") or "").strip() or None
        bot_id = str(body.get("bot_id") or "").strip() or None
        thread_id = str(body.get("thread_id") or "").strip() or None
        gateway.start_teach(vm_id, name=name, bot_id=bot_id, thread_id=thread_id)
        st = await _publish_computer_state(vm_id)
        return JSONResponse(status_code=status.HTTP_200_OK, content=st)

    @router.post("/api/v1/computers/{vm_id}/teach/stop")
    async def api_computer_teach_stop(vm_id: str, request: Request) -> JSONResponse:
        body = await _read_optional_json_object(request)
        override_name = str(body.get("name") or "").strip()
        recorded_name, bot_id, fallback_thread_id, steps = gateway.stop_teach(vm_id)
        final_name = override_name or recorded_name
        bot_name, thread_id = await _store_get_bot_info(store, bot_id, fallback_thread_id)

        skill_md = _compile_skill_markdown(final_name, steps)
        description = f"Recorded Teach-a-Task workflow with {len(steps)} step(s)."

        skill_obj = await _store_create_skill(
            store,
            bot_id=bot_id,
            name=final_name,
            description=description,
            content_md=skill_md,
            steps=steps,
        )
        artifact_obj = await _store_create_artifact(
            store,
            bot_id=bot_id,
            thread_id=thread_id,
            title=f"Skill: {final_name}",
            content_md=skill_md,
        )
        confirm_text = (
            f"Saved new Teach-a-Task skill **{final_name}** "
            f"({len(steps)} step(s) captured) to your Skills library."
        )
        message_obj = await _store_create_message(
            store,
            bot_id=bot_id,
            bot_name=bot_name,
            thread_id=thread_id,
            content=confirm_text,
            artifact=artifact_obj,
        )

        comp_status = await _publish_computer_state(vm_id)
        await _emit_event_bus(
            event_bus,
            "artifact.page.updated",
            {"artifact": artifact_obj},
            bot_id=bot_id,
            thread_id=thread_id,
        )
        await _emit_event_bus(
            event_bus,
            "message.completed",
            {"message_id": str(message_obj.get("id", "")), "message": message_obj},
            bot_id=bot_id,
            thread_id=thread_id,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": comp_status,
                "skill": _scrub(skill_obj),
                "artifact": _scrub(artifact_obj),
                "message": _scrub(message_obj),
            },
        )

    # ------------------------------------------------------------------
    # WebSockets (all verify `cap_token` query param)
    # ------------------------------------------------------------------

    @router.websocket("/ws/v1/computers/{vm_id}/vnc")
    async def ws_computer_vnc(websocket: WebSocket, vm_id: str) -> None:
        if not _ws_authorized(gateway, websocket, vm_id):
            await websocket.close(code=4401)
            return

        requested_protos = [
            p.strip().lower()
            for p in websocket.headers.get("sec-websocket-protocol", "").split(",")
            if p.strip()
        ]
        if "binary" in requested_protos:
            await websocket.accept(subprotocol="binary")
        else:
            await websocket.accept()

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(gateway.vnc_host, gateway.vnc_port),
                timeout=5.0,
            )
            assert reader is not None
            assert writer is not None
            tcp_reader = reader
            tcp_writer = writer
            await asyncio.wait_for(
                perform_backend_vnc_handshake(tcp_reader, tcp_writer, gateway.vnc_passwd_path),
                timeout=8.0,
            )
            leftover = await asyncio.wait_for(
                perform_client_none_handshake(websocket),
                timeout=8.0,
            )

            # Relay 1-byte ClientInit before enabling the post-ClientInit RFB Input Gate
            init_buf = bytearray(leftover)
            while len(init_buf) < 1:
                raw = await websocket.receive()
                if raw.get("type") == "websocket.disconnect":
                    return
                first_chunk = raw.get("bytes")
                if not isinstance(first_chunk, (bytes, bytearray)) or not first_chunk:
                    continue
                init_buf.extend(first_chunk)
            tcp_writer.write(bytes(init_buf[:1]))
            await tcp_writer.drain()
            post_init_bytes = bytes(init_buf[1:])

            gate = RfbInputGate()
            if post_init_bytes:
                initial_allowed = gate.feed(
                    post_init_bytes,
                    allow_input=(gateway.get_control_owner(vm_id) == "human_takeover"),
                )
                if initial_allowed:
                    tcp_writer.write(initial_allowed)
                    await tcp_writer.drain()

            async def _ws_to_vnc() -> None:
                while True:
                    raw = await websocket.receive()
                    if raw.get("type") == "websocket.disconnect":
                        break
                    chunk = raw.get("bytes")
                    if not isinstance(chunk, (bytes, bytearray)) or not chunk:
                        continue
                    allow_input = gateway.get_control_owner(vm_id) == "human_takeover"
                    filtered = gate.feed(bytes(chunk), allow_input=allow_input)
                    if filtered:
                        tcp_writer.write(filtered)
                        await tcp_writer.drain()

            async def _vnc_to_ws() -> None:
                while True:
                    data = await tcp_reader.read(65536)
                    if not data:
                        break
                    await websocket.send_bytes(data)

            up_task: asyncio.Task[None] = asyncio.create_task(_ws_to_vnc())
            down_task: asyncio.Task[None] = asyncio.create_task(_vnc_to_ws())
            try:
                done, pending = await asyncio.wait(
                    {up_task, down_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                for task in done:
                    with contextlib.suppress(
                        WebSocketDisconnect,
                        asyncio.CancelledError,
                        OSError,
                    ):
                        task.result()
            finally:
                for task in (up_task, down_task):
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
        except (OSError, TimeoutError, RfbHandshakeError):
            with contextlib.suppress(Exception):
                await websocket.close(code=1011)
        except WebSocketDisconnect:
            pass
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    @router.websocket("/ws/v1/computers/{vm_id}/screencast")
    async def ws_computer_screencast(websocket: WebSocket, vm_id: str) -> None:
        if not _ws_authorized(gateway, websocket, vm_id):
            await websocket.close(code=4401)
            return
        await websocket.accept()

        async def _send_state_and_frame() -> None:
            b_st = await live_browser.status()
            await websocket.send_json(
                {
                    "type": "status",
                    **b_st,
                    "control_owner": gateway.get_control_owner(vm_id),
                }
            )
            if b_st.get("running"):
                frame = await live_browser.capture_frame()
                if frame is not None:
                    await websocket.send_json(frame)

        await _send_state_and_frame()

        async def _reader() -> None:
            while True:
                raw = await websocket.receive()
                if raw.get("type") == "websocket.disconnect":
                    break
                raw_text = raw.get("text")
                if not isinstance(raw_text, str):
                    continue
                try:
                    msg = json.loads(raw_text)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(msg, dict):
                    continue
                ev_type = str(msg.get("type") or msg.get("action") or "").strip().lower()
                if not ev_type:
                    continue
                if ev_type == "ping":
                    await websocket.send_json({"type": "pong", "ts": _utc_now_iso()})
                    continue
                if ev_type == "status":
                    await _send_state_and_frame()
                    continue

                is_raw_input = ev_type in _RAW_BROWSER_INPUT_TYPES
                if is_raw_input and gateway.get_control_owner(vm_id) != "human_takeover":
                    await websocket.send_json(
                        {
                            "type": "blocked",
                            "message": "Take over control to send mouse or keyboard input.",
                        }
                    )
                    continue

                try:
                    if ev_type == "start":
                        url_arg = msg.get("url")
                        await live_browser.start(
                            initial_url=str(url_arg) if isinstance(url_arg, str) else None
                        )
                    elif ev_type == "stop":
                        await live_browser.stop()
                    elif ev_type == "navigate":
                        await live_browser.navigate(str(msg.get("url", "")))
                    elif ev_type == "back":
                        await live_browser.go_back()
                    elif ev_type == "forward":
                        await live_browser.go_forward()
                    elif ev_type == "reload":
                        await live_browser.reload()
                    elif is_raw_input:
                        await live_browser.handle_input(msg)
                    elif ev_type not in _NAV_BROWSER_TYPES:
                        continue

                    b_st = await live_browser.status()
                    url = str(b_st.get("url", ""))
                    title = str(b_st.get("title", ""))
                    desc = _describe_browser_action(msg, url=url)
                    tab_changed = gateway.update_browser_metadata(
                        vm_id,
                        url=url,
                        title=title,
                        step_summary=desc,
                    )
                    if gateway.is_teaching(vm_id):
                        step = gateway.record_teach_step(
                            vm_id,
                            action=ev_type,
                            description=desc,
                            url=url,
                        )
                        if step is not None:
                            await gateway.broadcast_control(
                                vm_id,
                                {
                                    "op": "teach.step_captured",
                                    "vm_id": vm_id,
                                    "step": step,
                                    "teach_steps_count": step["step_index"],
                                },
                            )
                    if tab_changed:
                        await gateway.broadcast_control(
                            vm_id,
                            {
                                "op": "browser.tab_changed",
                                "vm_id": vm_id,
                                "url": _scrub_str(url),
                                "title": _scrub_str(title),
                            },
                        )
                    await _send_state_and_frame()
                except Exception as exc:
                    await websocket.send_json({"type": "error", "message": _scrub_str(str(exc))})

        async def _ticker() -> None:
            while True:
                await asyncio.sleep(0.5)
                if live_browser.running:
                    frame = await live_browser.capture_frame()
                    if frame is not None:
                        await websocket.send_json(frame)

        reader_task: asyncio.Task[None] = asyncio.create_task(_reader())
        ticker_task: asyncio.Task[None] = asyncio.create_task(_ticker())
        try:
            done, pending = await asyncio.wait(
                {reader_task, ticker_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in done:
                with contextlib.suppress(WebSocketDisconnect, asyncio.CancelledError):
                    task.result()
        except WebSocketDisconnect:
            pass
        finally:
            for task in (reader_task, ticker_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

    @router.websocket("/ws/v1/computers/{vm_id}/control")
    async def ws_computer_control(websocket: WebSocket, vm_id: str) -> None:
        if not _ws_authorized(gateway, websocket, vm_id):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        gateway.register_control_socket(vm_id, websocket)
        try:
            initial_st = await gateway.get_status(vm_id, live_browser=live_browser)
            await websocket.send_json({"op": "computer.state", "status": initial_st})
            while True:
                raw = await websocket.receive()
                if raw.get("type") == "websocket.disconnect":
                    break
                raw_text = raw.get("text")
                if not isinstance(raw_text, str):
                    continue
                try:
                    msg = json.loads(raw_text)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(msg, dict):
                    continue
                op = str(msg.get("op") or "").strip().lower()
                if op == "lease.heartbeat":
                    req_lease = msg.get("lease_id")
                    ok, active_lease, exp_iso = gateway.renew_lease(
                        vm_id,
                        lease_id=str(req_lease) if isinstance(req_lease, str) else None,
                    )
                    if ok:
                        await websocket.send_json(
                            {
                                "op": "lease.heartbeat.ack",
                                "vm_id": vm_id,
                                "lease_id": active_lease,
                                "lease_expires_at": exp_iso,
                            }
                        )
                    else:
                        await websocket.send_json(
                            {
                                "op": "lease.revoked",
                                "vm_id": vm_id,
                                "lease_id": active_lease,
                                "reason": "lease_expired_or_inactive",
                            }
                        )
                elif op == "viewport.resize":
                    try:
                        w = coerce_finite_int(msg.get("width", 1280))
                        h = coerce_finite_int(msg.get("height", 800))
                    except (TypeError, ValueError, OverflowError):
                        w, h = 1280, 800
                    bw, bh = gateway.set_viewport(vm_id, width=w, height=h)
                    await websocket.send_json(
                        {
                            "op": "viewport.resize.ack",
                            "vm_id": vm_id,
                            "width": bw,
                            "height": bh,
                        }
                    )
                elif op == "clipboard.push":
                    raw_text = msg.get("text")
                    pushed = (
                        await _push_x11_clipboard(raw_text)
                        if isinstance(raw_text, str)
                        else False
                    )
                    await websocket.send_json(
                        {
                            "op": "clipboard.push.ack",
                            "vm_id": vm_id,
                            "ok": pushed,
                        }
                    )
                elif op == "ping":
                    await websocket.send_json({"op": "pong", "ts": _utc_now_iso()})
        except WebSocketDisconnect:
            pass
        finally:
            gateway.unregister_control_socket(vm_id, websocket)

    @router.websocket("/ws/v1/computers/{vm_id}/pty/{session_id}")
    async def ws_computer_pty(websocket: WebSocket, vm_id: str, session_id: str) -> None:
        del session_id
        if not _ws_authorized(gateway, websocket, vm_id):
            await websocket.close(code=4401)
            return
        await websocket.accept()

        project_param = websocket.query_params.get("project", "").strip()
        cwd: Path
        if project_param:
            try:
                cwd = resolve_project_dir(gateway.projects_root, project_param)
            except ValueError:
                await websocket.close(code=1008)
                return
        else:
            default_dir = gateway.projects_root / gateway.default_project
            if default_dir.is_dir():
                cwd = default_dir
            elif gateway.projects_root.is_dir():
                cwd = gateway.projects_root
            else:
                cwd = Path.cwd()

        term = LiveTerminalSession(cwd=cwd)

        async def _pty_to_ws() -> None:
            while True:
                chunk = await term.output_queue.get()
                if chunk is None:
                    with contextlib.suppress(Exception):
                        await websocket.close(code=1000)
                    break
                await websocket.send_text(chunk)

        async def _ws_to_pty() -> None:
            while True:
                frame = await websocket.receive()
                frame_type = frame.get("type")
                if frame_type == "websocket.disconnect":
                    break
                raw_bytes = frame.get("bytes")
                if isinstance(raw_bytes, (bytes, bytearray)):
                    term.write(bytes(raw_bytes).decode("utf-8", errors="replace"))
                    continue
                raw_text = frame.get("text")
                if not isinstance(raw_text, str):
                    continue
                if raw_text.startswith("{"):
                    parsed: Any = None
                    with contextlib.suppress(json.JSONDecodeError, ValueError):
                        parsed = json.loads(raw_text)
                    if isinstance(parsed, dict):
                        op = str(parsed.get("op") or parsed.get("type") or "").strip().lower()
                        if op == "resize":
                            with contextlib.suppress(TypeError, ValueError, OverflowError):
                                term.resize(
                                    cols=coerce_finite_int(parsed.get("cols", 100)),
                                    rows=coerce_finite_int(parsed.get("rows", 28)),
                                )
                            continue
                        if op == "signal":
                            sig_val = str(parsed.get("sig") or parsed.get("signal") or "SIGINT")
                            _send_pty_signal(term, sig_val)
                            continue
                        if op == "input":
                            term.write(str(parsed.get("data", "")))
                            continue
                term.write(raw_text)

        out_task: asyncio.Task[None] = asyncio.create_task(_pty_to_ws())
        in_task: asyncio.Task[None] = asyncio.create_task(_ws_to_pty())
        try:
            done, pending = await asyncio.wait(
                {out_task, in_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in done:
                with contextlib.suppress(WebSocketDisconnect, asyncio.CancelledError):
                    task.result()
        except WebSocketDisconnect:
            pass
        finally:
            for task in (out_task, in_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            term.close()

    return router
