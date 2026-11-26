"""Local project discovery and Antigravity (`agy`) conversation continuity helpers."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.storage.redaction import contains_unredacted_secret_strict, redact_payload_strict

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_CONV_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
_USER_REQ_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.DOTALL)
_INLINE_TOKEN_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pou]_[A-Za-z0-9_]{8,})\b")


def _scrub_text(value: str) -> str:
    scrubbed = str(redact_payload_strict(value))
    return _INLINE_TOKEN_RE.sub("[REDACTED]", scrubbed)


def default_projects_root() -> Path:
    """Return configured Projects directory or ~/Projects."""
    raw = os.environ.get("CONTROLBOT_PROJECTS_ROOT", "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / "Projects"


def default_agy_brain_root() -> Path:
    """Return configured Antigravity brain directory or ~/.gemini/antigravity-cli/brain."""
    raw = os.environ.get("CONTROLBOT_AGY_BRAIN_ROOT", "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".gemini" / "antigravity-cli" / "brain"


def list_local_projects(projects_root: Path) -> list[dict[str, Any]]:
    """List non-hidden project folders directly under projects_root, newest first."""
    if not projects_root.is_dir():
        return []
    resolved_root = projects_root.resolve()
    items: list[tuple[float, dict[str, Any]]] = []
    try:
        entries = list(projects_root.iterdir())
    except OSError:
        return []

    for entry in entries:
        if entry.name.startswith("."):
            continue
        try:
            resolved = entry.resolve()
            if not resolved.is_dir() or not resolved.is_relative_to(resolved_root):
                continue
            mtime = resolved.stat().st_mtime
        except OSError:
            continue

        updated_iso = datetime.fromtimestamp(mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        record: dict[str, Any] = {
            "name": entry.name,
            "path": str(resolved),
            "is_git": (resolved / ".git").exists(),
            "has_readme": (resolved / "README.md").exists(),
            "updated_at": updated_iso,
        }
        items.append((mtime, record))

    items.sort(key=lambda pair: (-pair[0], str(pair[1]["name"]).lower()))
    return [pair[1] for pair in items]


def resolve_project_dir(projects_root: Path, project_name: str) -> Path:
    """Resolve and validate a single project folder name inside projects_root."""
    cleaned = project_name.strip()
    if (
        not cleaned
        or cleaned in {".", ".."}
        or cleaned.startswith(".")
        or "/" in cleaned
        or "\\" in cleaned
        or "\x00" in cleaned
    ):
        raise ValueError(f"Invalid project_name: {project_name!r}")
    if not projects_root.is_dir():
        raise ValueError(f"Projects root directory does not exist: {projects_root}")
    resolved_root = projects_root.resolve()
    candidate = (projects_root / cleaned).resolve()
    if not candidate.is_relative_to(resolved_root) or candidate == resolved_root:
        raise ValueError(f"Project path escapes projects root: {project_name!r}")
    if not candidate.is_dir():
        raise ValueError(f"Unknown project folder: {project_name!r}")
    return candidate


def _extract_transcript_preview(transcript_path: Path) -> tuple[str, bool]:
    """Extract a short redacted preview and whether the thread started with USER_EXPLICIT."""
    try:
        with transcript_path.open("r", encoding="utf-8", errors="replace") as handle:
            snippet = handle.read(16384)
    except OSError:
        return "", False

    first_text = ""
    is_user = False
    for raw_line in snippet.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        content = obj.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        source = str(obj.get("source", ""))
        msg_type = str(obj.get("type", ""))
        if msg_type == "USER_INPUT" or source == "USER_EXPLICIT":
            is_user = source == "USER_EXPLICIT"
            match = _USER_REQ_RE.search(content)
            raw_text = match.group(1) if match else content
            first_text = " ".join(raw_text.split())
            break

    if not first_text:
        return "", is_user

    scrubbed = _scrub_text(first_text)
    if contains_unredacted_secret_strict(scrubbed):
        scrubbed = "[REDACTED]"
    if len(scrubbed) > 90:
        scrubbed = scrubbed[:87].rstrip() + "..."
    return scrubbed, is_user


def list_agy_conversations(brain_root: Path, *, limit: int = 25) -> list[dict[str, Any]]:
    """List recent Antigravity conversations in brain_root with transcript logs."""
    if not brain_root.is_dir() or limit <= 0:
        return []
    resolved_root = brain_root.resolve()
    found: list[tuple[float, dict[str, Any]]] = []
    try:
        entries = list(brain_root.iterdir())
    except OSError:
        return []

    for entry in entries:
        if not _UUID_RE.fullmatch(entry.name):
            continue
        try:
            resolved_dir = entry.resolve()
            if not resolved_dir.is_dir() or not resolved_dir.is_relative_to(resolved_root):
                continue
            transcript = resolved_dir / ".system_generated" / "logs" / "transcript.jsonl"
            if not transcript.is_file():
                continue
            stat = transcript.stat()
        except OSError:
            continue

        preview, is_user = _extract_transcript_preview(transcript)
        updated_iso = datetime.fromtimestamp(stat.st_mtime, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        found.append(
            (
                stat.st_mtime,
                {
                    "conversation_id": entry.name,
                    "updated_at": updated_iso,
                    "size_bytes": stat.st_size,
                    "preview": preview,
                    "is_user_explicit": is_user,
                    "resume_command": f"agy --resume {entry.name}",
                },
            )
        )

    found.sort(key=lambda pair: (-pair[0], str(pair[1]["conversation_id"])))
    return [pair[1] for pair in found[:limit]]


def find_agy_executable() -> str | None:
    """Locate the Antigravity CLI binary if installed on this host."""
    preferred = Path.home() / ".local" / "bin" / "agy"
    if preferred.is_file() and os.access(preferred, os.X_OK):
        return str(preferred)
    return shutil.which("agy")


async def send_agy_prompt(
    *,
    prompt: str,
    conversation_id: str | None = None,
    project_dir: Path | None = None,
    model: str = "gemini-4-carbon-low",
    timeout_s: float = 120.0,
) -> dict[str, Any]:
    """Execute one non-hydrogen Antigravity CLI turn, optionally resuming conversation_id."""
    cleaned_prompt = prompt.strip()
    if not cleaned_prompt:
        raise ValueError("prompt must not be empty.")

    cleaned_model = model.strip()
    if not cleaned_model:
        raise ValueError("model must not be empty.")
    if "hydrogen" in cleaned_model.lower():
        raise ValueError("Hydrogen models are disabled by policy; use carbon/neon instead.")

    cleaned_cid: str | None = None
    if conversation_id is not None and conversation_id.strip():
        cleaned_cid = conversation_id.strip()
        if not _CONV_ID_RE.fullmatch(cleaned_cid):
            raise ValueError(f"Invalid conversation_id format: {conversation_id!r}")

    agy_bin = find_agy_executable()
    if agy_bin is None:
        raise FileNotFoundError("Antigravity CLI ('agy') is not installed on this host.")

    bounded_timeout = max(5, int(round(timeout_s)))
    args = [
        agy_bin,
        "-p",
        cleaned_prompt,
        "--model",
        cleaned_model,
        "--output-format",
        "json",
        "--disable-slash-commands",
        "--print-timeout",
        f"{bounded_timeout}s",
    ]
    if cleaned_cid is not None:
        args.extend(["--conversation", cleaned_cid])

    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(project_dir) if project_dir is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(bounded_timeout + 15),
        )
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"agy execution exceeded {bounded_timeout}s timeout.") from exc

    stdout_text = stdout_b.decode("utf-8", errors="replace").strip()
    stderr_text = stderr_b.decode("utf-8", errors="replace").strip()
    parsed: dict[str, Any] | None = None
    for line in reversed(stdout_text.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            parsed = candidate
            break

    if parsed is None:
        detail = stderr_text or stdout_text or f"exit code {proc.returncode}"
        raise RuntimeError(f"agy returned non-JSON output: {detail[:300]}")

    status_val = str(parsed.get("status", ""))
    if proc.returncode != 0 or status_val != "SUCCESS":
        err_msg = str(parsed.get("error") or stderr_text or f"status={status_val}")
        raise RuntimeError(f"agy call failed ({status_val or proc.returncode}): {err_msg[:300]}")

    resolved_cid = str(parsed.get("conversation_id") or cleaned_cid or "")
    payload: dict[str, Any] = {
        "conversation_id": resolved_cid,
        "status": status_val,
        "response": _scrub_text(str(parsed.get("response", ""))),
        "model": cleaned_model,
        "duration_seconds": parsed.get("duration_seconds"),
        "usage": parsed.get("usage") if isinstance(parsed.get("usage"), dict) else {},
        "resume_command": f"agy --resume {resolved_cid}" if resolved_cid else "",
    }
    scrubbed: dict[str, Any] = redact_payload_strict(payload)
    if contains_unredacted_secret_strict(scrubbed):
        raise RuntimeError("agy response failed strict secret redaction check.")
    return scrubbed
