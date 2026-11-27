"""SQLite WAL persistence store for Grok Bot UX/UI workspace entities."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.storage.audit_chain import (
    append_chained_audit_row,
    ensure_workspace_audit_schema,
    verify_chain,
)
from src.web.v1.events import scrub_v1_payload, utc_iso_now
from src.web.v1.schemas import (
    MAX_AUTO_REVIEW_RULE_LEN,
    MAX_AUTO_REVIEW_RULES_PER_BUCKET,
    MAX_ROSTER_ITEMS,
    MAX_ROUTINES_PER_BOT,
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_VAULT_V1_PREFIX = b"v1:"
_VAULT_V2G_PREFIX = b"v2g:"
_VAULT_V2H_PREFIX = b"v2h:"
_VAULT_AAD = b"grokbot-vault-v2"
SCHEMA_VERSION = 2


class StoreNotFoundError(Exception):
    """Raised when a requested workspace entity does not exist."""


class StoreConflictError(Exception):
    """Raised on idempotency conflicts or invalid state transitions."""


class StoreValidationError(Exception):
    """Raised when store-level limits or integrity checks fail."""


def _slugify(value: str) -> str:
    cleaned = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return cleaned or f"skill-{uuid.uuid4().hex[:6]}"


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(prev)
        counter += 1
    return bytes(okm[:length])


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        normalized = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _loads_json(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def _resolve_workspace_db_path(db_path: Path | str | None) -> Path:
    if db_path is None:
        return Path("var/grokbot_workspace.sqlite3")
    path = Path(db_path)
    if path.name.endswith("_workspace.sqlite3"):
        return path
    return path.with_name(f"{path.stem}_workspace.sqlite3")


class WorkspaceStore:
    """Thread-safe SQLite WAL store for bots, threads, HITL cards, vault, routines, and skills."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = _resolve_workspace_db_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_depth = 0
        self._vault_key = self._load_or_create_vault_key()
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            journal_row = self._conn.execute("PRAGMA journal_mode=WAL;").fetchone()
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            if str(self.db_path) != ":memory:":
                mode = str(journal_row[0]).lower() if journal_row is not None else ""
                if mode != "wal":
                    self._conn.close()
                    raise StoreValidationError(
                        f"SQLite WAL mode could not be enabled on {self.db_path} (got {mode!r})."
                    )
            self._init_schema()
            self._seed_defaults()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def write_tx(self) -> Iterator[sqlite3.Connection]:
        """Re-entrant thread-safe BEGIN IMMEDIATE / SAVEPOINT write transaction."""
        with self._lock:
            depth = self._tx_depth
            if depth == 0:
                self._conn.execute("BEGIN IMMEDIATE;")
                self._tx_depth = 1
                try:
                    yield self._conn
                    self._conn.execute("COMMIT;")
                except BaseException:
                    if self._conn.in_transaction:
                        self._conn.execute("ROLLBACK;")
                    raise
                finally:
                    self._tx_depth = 0
            else:
                sp = f"sp_tx_{depth}"
                self._conn.execute(f"SAVEPOINT {sp};")
                self._tx_depth = depth + 1
                try:
                    yield self._conn
                    self._conn.execute(f"RELEASE SAVEPOINT {sp};")
                except BaseException:
                    if self._conn.in_transaction:
                        self._conn.execute(f"ROLLBACK TO SAVEPOINT {sp};")
                        self._conn.execute(f"RELEASE SAVEPOINT {sp};")
                    raise
                finally:
                    self._tx_depth = depth

    def _load_or_create_vault_key(self) -> bytes:
        key_path = self.db_path.with_name(f".{self.db_path.stem}.vault.key")
        if key_path.is_symlink():
            raise StoreValidationError(f"Refusing symlink vault key file: {key_path}")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if key_path.exists():
            fd = os.open(str(key_path), os.O_RDONLY | nofollow)
            try:
                raw = os.read(fd, 256)
            finally:
                os.close(fd)
            if len(raw) == 32:
                with contextlib.suppress(OSError):
                    os.chmod(key_path, 0o600)
                return raw
            if len(raw) > 32:
                stripped = raw.strip()
                if len(stripped) == 64:
                    try:
                        decoded = bytes.fromhex(stripped.decode("ascii"))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise StoreValidationError(
                            f"Corrupt vault key file: invalid hex key in {key_path}"
                        ) from exc
                    if len(decoded) == 32:
                        with contextlib.suppress(OSError):
                            os.chmod(key_path, 0o600)
                        return decoded
                raise StoreValidationError(
                    f"Corrupt vault key file: unexpected length ({len(raw)} bytes)"
                )
            if len(raw) > 0:
                raise StoreValidationError(
                    f"Corrupt vault key file: unexpected length ({len(raw)} bytes)"
                )
        key_bytes = secrets.token_bytes(32)
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | nofollow, 0o600)
        try:
            os.write(fd, key_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.chmod(key_path, 0o600)
        return key_bytes

    @staticmethod
    def _try_aesgcm_cls() -> Any | None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        except ImportError:
            return None
        return AESGCM

    def _encrypt_vault_payload(self, data: dict[str, str]) -> str:
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        aesgcm_cls = self._try_aesgcm_cls()
        if aesgcm_cls is not None:
            nonce = secrets.token_bytes(12)
            ct = aesgcm_cls(self._vault_key).encrypt(nonce, plaintext, _VAULT_AAD)
            return base64.b64encode(_VAULT_V2G_PREFIX + nonce + ct).decode("ascii")

        nonce = secrets.token_bytes(16)
        enc_key = _hkdf_sha256(self._vault_key, nonce, b"grokbot-vault-v2-enc", 32)
        mac_key = _hkdf_sha256(self._vault_key, nonce, b"grokbot-vault-v2-mac", 32)
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(plaintext):
            block = hmac.new(
                enc_key,
                nonce + counter.to_bytes(8, "big"),
                hashlib.sha256,
            ).digest()
            keystream.extend(block)
            counter += 1
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream, strict=False))
        tag = hmac.new(
            mac_key,
            _VAULT_V2H_PREFIX + _VAULT_AAD + nonce + ciphertext,
            hashlib.sha256,
        ).digest()
        return base64.b64encode(_VAULT_V2H_PREFIX + nonce + tag + ciphertext).decode("ascii")

    def _decrypt_vault_payload(self, blob: str) -> dict[str, str]:
        raw = base64.b64decode(blob.encode("ascii"))
        if raw.startswith(_VAULT_V2G_PREFIX):
            aesgcm_cls = self._try_aesgcm_cls()
            if aesgcm_cls is None:
                raise ValueError("AES-GCM vault payload requires cryptography package.")
            body = raw[len(_VAULT_V2G_PREFIX) :]
            if len(body) < 28:
                raise ValueError("Corrupted v2g vault secret payload.")
            nonce = body[:12]
            ct = body[12:]
            plaintext = aesgcm_cls(self._vault_key).decrypt(nonce, ct, _VAULT_AAD)
        elif raw.startswith(_VAULT_V2H_PREFIX):
            body = raw[len(_VAULT_V2H_PREFIX) :]
            if len(body) < 48:
                raise ValueError("Corrupted v2h vault secret payload.")
            nonce = body[:16]
            tag = body[16:48]
            ciphertext = body[48:]
            enc_key = _hkdf_sha256(self._vault_key, nonce, b"grokbot-vault-v2-enc", 32)
            mac_key = _hkdf_sha256(self._vault_key, nonce, b"grokbot-vault-v2-mac", 32)
            expected_tag = hmac.new(
                mac_key,
                _VAULT_V2H_PREFIX + _VAULT_AAD + nonce + ciphertext,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Vault secret authentication tag mismatch.")
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ciphertext):
                block = hmac.new(
                    enc_key,
                    nonce + counter.to_bytes(8, "big"),
                    hashlib.sha256,
                ).digest()
                keystream.extend(block)
                counter += 1
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream, strict=False))
        elif raw.startswith(_VAULT_V1_PREFIX):
            body = raw[len(_VAULT_V1_PREFIX) :]
            if len(body) < 48:
                raise ValueError("Corrupted v1 vault secret payload.")
            nonce = body[:16]
            tag = body[16:48]
            ciphertext = body[48:]
            enc_key = hmac.new(self._vault_key, b"enc:" + nonce, hashlib.sha256).digest()
            mac_key = hmac.new(self._vault_key, b"mac:" + nonce, hashlib.sha256).digest()
            expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Vault secret authentication tag mismatch.")
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ciphertext):
                block = hmac.new(enc_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
                keystream.extend(block)
                counter += 1
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream, strict=False))
        else:
            raise ValueError("Unsupported vault secret payload version.")

        parsed = json.loads(plaintext.decode("utf-8"))
        if not isinstance(parsed, dict):
            return {}
        return {str(k): str(v) for k, v in parsed.items()}

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sections (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                thread_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                role_prompt TEXT NOT NULL DEFAULT '',
                about TEXT NOT NULL DEFAULT '',
                avatar_shape TEXT NOT NULL DEFAULT 'sparkle',
                avatar_color TEXT NOT NULL DEFAULT '#7C3AED',
                avatar_eyes_large INTEGER NOT NULL DEFAULT 0,
                engine_id TEXT NOT NULL DEFAULT 'agy',
                model_id TEXT NOT NULL DEFAULT 'gemini-4-carbon-low',
                thinking_level TEXT NOT NULL DEFAULT 'medium',
                project_name TEXT,
                pinned INTEGER NOT NULL DEFAULT 0,
                section_id TEXT REFERENCES sections(id) ON DELETE SET NULL,
                hidden INTEGER NOT NULL DEFAULT 0,
                is_primary INTEGER NOT NULL DEFAULT 0,
                is_team_bot INTEGER NOT NULL DEFAULT 0,
                unread_count INTEGER NOT NULL DEFAULT 0,
                needs_attention INTEGER NOT NULL DEFAULT 0,
                status_state TEXT NOT NULL DEFAULT 'idle',
                status_subtext TEXT NOT NULL DEFAULT '',
                computer_active INTEGER NOT NULL DEFAULT 0,
                timezone TEXT NOT NULL DEFAULT 'UTC',
                drafts_enabled INTEGER NOT NULL DEFAULT 1,
                conversation_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                thread_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                bot_ids_json TEXT NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0,
                section_id TEXT REFERENCES sections(id) ON DELETE SET NULL,
                hidden INTEGER NOT NULL DEFAULT 0,
                unread_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT UNIQUE NOT NULL,
                thread_id TEXT NOT NULL,
                sender_type TEXT NOT NULL,
                sender_bot_id TEXT,
                sender_name TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                thinking_text TEXT NOT NULL DEFAULT '',
                reply_to_id TEXT,
                mentions_json TEXT NOT NULL DEFAULT '[]',
                attachments_json TEXT NOT NULL DEFAULT '[]',
                tool_calls_json TEXT NOT NULL DEFAULT '[]',
                artifacts_json TEXT NOT NULL DEFAULT '[]',
                reactions_json TEXT NOT NULL DEFAULT '{}',
                memory_diffs_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                conversation_id TEXT,
                model_id TEXT,
                status TEXT NOT NULL DEFAULT 'done',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_thread_seq
                ON messages(thread_id, seq);

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                thread_id TEXT,
                bot_id TEXT,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                thread_id TEXT,
                message_id TEXT,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                content_md TEXT NOT NULL DEFAULT '',
                url TEXT,
                file_path TEXT,
                mime_type TEXT NOT NULL DEFAULT 'text/markdown',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                pinned INTEGER NOT NULL DEFAULT 0,
                share_scope TEXT NOT NULL DEFAULT 'private',
                version INTEGER NOT NULL DEFAULT 1,
                superseded_by_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifacts_bot
                ON artifacts(bot_id, updated_at);

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'standard',
                title TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT 'vm:default',
                risk_banner TEXT,
                arguments_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                allow_always_allowed INTEGER NOT NULL DEFAULT 1,
                waiting_for_user TEXT,
                decision_by TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                pending_context_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_thread
                ON approvals(thread_id, created_at);

            CREATE TABLE IF NOT EXISTS drafts (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                channel_type TEXT NOT NULL DEFAULT 'email',
                fields_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_drafts_thread
                ON drafts(thread_id, created_at);

            CREATE TABLE IF NOT EXISTS secure_forms (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'form',
                domain TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                fields_json TEXT NOT NULL DEFAULT '[]',
                allow_vault_save INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_secure_forms_thread
                ON secure_forms(thread_id, created_at);

            CREATE TABLE IF NOT EXISTS auto_review_rules (
                id TEXT PRIMARY KEY,
                bucket TEXT NOT NULL,
                rule_text TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_secrets (
                id TEXT PRIMARY KEY,
                bot_id TEXT,
                name TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                username_hint TEXT NOT NULL DEFAULT '',
                field_names_json TEXT NOT NULL DEFAULT '[]',
                encrypted_payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS routines (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                name TEXT NOT NULL,
                instruction TEXT NOT NULL,
                schedule_type TEXT NOT NULL DEFAULT 'cron',
                cron_expr TEXT,
                timezone TEXT NOT NULL DEFAULT 'UTC',
                enabled INTEGER NOT NULL DEFAULT 1,
                webhook_key TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'only_me',
                last_run_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_routines_bot
                ON routines(bot_id);

            CREATE TABLE IF NOT EXISTS routine_runs (
                id TEXT PRIMARY KEY,
                routine_id TEXT NOT NULL REFERENCES routines(id) ON DELETE CASCADE,
                bot_id TEXT NOT NULL,
                trigger TEXT NOT NULL DEFAULT 'manual',
                status TEXT NOT NULL DEFAULT 'running',
                summary TEXT NOT NULL DEFAULT '',
                error TEXT,
                message_id TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_routine_runs_routine
                ON routine_runs(routine_id, started_at);

            CREATE TABLE IF NOT EXISTS skills (
                id TEXT PRIMARY KEY,
                bot_id TEXT,
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                content_md TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'custom',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connected_apps (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'connected',
                config_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS idempotency_keys (
                scope TEXT NOT NULL,
                idem_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (scope, idem_key)
            );

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sse_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                epoch TEXT NOT NULL,
                event_type TEXT NOT NULL,
                bot_id TEXT,
                thread_id TEXT,
                turn_id TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sse_events_epoch_seq
                ON sse_events(epoch, seq);

            CREATE TABLE IF NOT EXISTS computer_vms (
                vm_id TEXT PRIMARY KEY,
                control_owner TEXT NOT NULL DEFAULT 'agent',
                lease_id TEXT,
                lease_owner TEXT,
                lease_expires_at REAL,
                active_url TEXT NOT NULL DEFAULT '',
                active_tab_title TEXT NOT NULL DEFAULT '',
                active_step_summary TEXT,
                display_mode TEXT NOT NULL DEFAULT 'vnc',
                viewport_width INTEGER NOT NULL DEFAULT 1280,
                viewport_height INTEGER NOT NULL DEFAULT 800,
                is_teaching_task INTEGER NOT NULL DEFAULT 0,
                teach_name TEXT,
                teach_bot_id TEXT,
                teach_thread_id TEXT,
                teach_started_at REAL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS teach_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vm_id TEXT NOT NULL REFERENCES computer_vms(vm_id) ON DELETE CASCADE,
                step_index INTEGER NOT NULL,
                action TEXT NOT NULL,
                description TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                ts TEXT NOT NULL,
                UNIQUE(vm_id, step_index)
            );
            CREATE INDEX IF NOT EXISTS idx_teach_steps_vm
                ON teach_steps(vm_id, step_index);
            """
        )
        now = utc_iso_now()
        with self.write_tx() as conn:
            ensure_workspace_audit_schema(conn)
            conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
                VALUES (1, 'baseline_workspace_schema', ?)
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
                VALUES (2, 'm2_wal_sse_audit_computer_state', ?)
                """,
                (now,),
            )
            msg_cols = {
                str(r[1]) for r in conn.execute("PRAGMA table_info(messages)").fetchall()
            }
            if "metadata_json" not in msg_cols:
                conn.execute(
                    "ALTER TABLE messages ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';"
                )
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

    def _seed_defaults(self) -> None:
        with self.write_tx():
            row = self._conn.execute(
                "SELECT value FROM kv_meta WHERE key = 'seeded_v1'"
            ).fetchone()
            if row is not None:
                return
            self._seed_defaults_inner()

    def _seed_defaults_inner(self) -> None:

        now = utc_iso_now()
        default_bots: list[tuple[Any, ...]] = [
            (
                "bot_chief",
                "thr_bot_chief",
                "Chief of Staff",
                (
                    "You are Chief of Staff, an executive coordinator bot for ControlBot. "
                    "Coordinate tasks, summarize workspace status, delegate to specialists, "
                    "and produce clear interactive pages when structured deliverables help."
                ),
                "Primary workspace coordinator & planning assistant.",
                "sparkle",
                "#7C3AED",
                0,
                "agy",
                "gemini-4-carbon-low",
                "medium",
                "Grokbotclon",
                1,
                None,
                0,
                1,
                0,
                0,
                0,
                "idle",
                "Nothing is blocked",
                0,
                "UTC",
                1,
                None,
                now,
                now,
            ),
            (
                "bot_ops",
                "thr_bot_ops",
                "ControlBot Ops",
                (
                    "You are ControlBot Ops, a systems and industrial operations engineer. "
                    "Inspect workspace files, diagnose services, execute safe terminal tasks, "
                    "and verify industrial telemetry rigorously."
                ),
                "Industrial runtime & infrastructure diagnostics specialist.",
                "square",
                "#0EA5E9",
                0,
                "agy",
                "gemini-4-carbon-low",
                "medium",
                "Grokbotclon",
                1,
                None,
                0,
                0,
                0,
                0,
                0,
                "idle",
                "Ready for industrial & system tasks",
                0,
                "UTC",
                1,
                None,
                now,
                now,
            ),
            (
                "bot_browser",
                "thr_bot_browser",
                "Browser Runner",
                (
                    "You are Browser Runner, a web automation specialist operating on the live "
                    "VM desktop and Playwright browser. Navigate pages, extract structured data, "
                    "and request secure forms whenever credentials are required."
                ),
                "Live browser & VM desktop automation specialist.",
                "clover",
                "#10B981",
                0,
                "agy",
                "gemini-4-carbon-low",
                "medium",
                "Grokbotclon",
                0,
                None,
                0,
                0,
                0,
                0,
                0,
                "idle",
                "Standing by on VM desktop",
                0,
                "UTC",
                1,
                None,
                now,
                now,
            ),
        ]
        self._conn.executemany(
            """
            INSERT OR IGNORE INTO bots (
                id, thread_id, name, role_prompt, about, avatar_shape, avatar_color,
                avatar_eyes_large, engine_id, model_id, thinking_level, project_name,
                pinned, section_id, hidden, is_primary, is_team_bot, unread_count,
                needs_attention, status_state, status_subtext, computer_active,
                timezone, drafts_enabled, conversation_id, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            default_bots,
        )

        default_apps: list[tuple[Any, ...]] = [
            (
                "app_agy",
                "Antigravity CLI (agy)",
                "agent",
                "Local Antigravity coding & reasoning CLI engine",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_vnc",
                "Linux VM Desktop (noVNC)",
                "computer",
                "Interactive virtual desktop over RFB/noVNC with input gating",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_playwright",
                "Live Browser (Playwright)",
                "browser",
                "Interactive persistent Chromium controller",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_pty",
                "Interactive Terminal (PTY)",
                "terminal",
                "Real pseudo-terminal shell scoped to workspace projects",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_files",
                "Workspace Files",
                "files",
                "Safe project file browsing, editing, and uploads",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_runtime",
                "ControlBot Industrial Runtime",
                "industrial",
                "Verified task coordinator with SCADA and maintenance adapters",
                1,
                "connected",
                "{}",
                now,
            ),
            (
                "app_webhooks",
                "Routine Webhooks",
                "automation",
                "Authenticated webhook triggers for scheduled bot routines",
                1,
                "connected",
                "{}",
                now,
            ),
        ]
        self._conn.executemany(
            """
            INSERT OR IGNORE INTO connected_apps (
                id, name, category, description, enabled, status, config_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            default_apps,
        )

        self._conn.execute(
            """
            INSERT OR IGNORE INTO skills (
                id, bot_id, name, slug, description, content_md, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "skl_summarize_workspace",
                None,
                "summarize-workspace",
                "summarize-workspace",
                "Summarize repository layout, active services, and key entrypoints.",
                (
                    "Inspect the active project directory structure, identify key modules, "
                    "configuration files, and summarize current status in concise Markdown."
                ),
                "system",
                now,
                now,
            ),
        )

        self._conn.execute(
            """
            INSERT OR IGNORE INTO routines (
                id, bot_id, name, instruction, schedule_type, cron_expr, timezone,
                enabled, webhook_key, visibility, last_run_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "rtn_morning_health",
                "bot_chief",
                "Morning health check",
                "Inspect workspace health, summarize any blockers, and report concise status.",
                "cron",
                "0 9 * * *",
                "UTC",
                0,
                f"whk_{secrets.token_hex(16)}",
                "only_me",
                None,
                now,
                now,
            ),
        )

        self._conn.execute(
            """
            INSERT OR IGNORE INTO auto_review_rules (
                id, bucket, rule_text, sort_order, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "arr_default_destructive",
                "ask_first",
                "Ask before deleting files or running destructive shell commands",
                0,
                now,
            ),
        )

        default_settings = {
            "theme": "light",
            "default_model_id": "gemini-4-carbon-low",
            "default_engine_id": "agy",
            "default_project_name": "Grokbotclon",
            "allow_hydrogen": False,
            "include_browser_context": True,
            "notifications_enabled": True,
            "sound_enabled": False,
            "auto_open_computer": True,
            "timezone": "UTC",
            "display_name": "Operator",
            "updated_at": now,
        }
        self._conn.execute(
            """
            INSERT OR IGNORE INTO settings (id, payload_json, updated_at)
            VALUES ('default', ?, ?)
            """,
            (json.dumps(default_settings), now),
        )

        self._conn.execute(
            "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('seeded_v1', '1')"
        )

    # ------------------------------------------------------------------
    # Row serializers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_section(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "sort_order": int(row["sort_order"]),
            "created_at": str(row["created_at"]),
        }

    @staticmethod
    def _row_to_bot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "thread_id": str(row["thread_id"]),
            "name": str(row["name"]),
            "role_prompt": str(row["role_prompt"]),
            "about": str(row["about"]),
            "avatar_shape": str(row["avatar_shape"]),
            "avatar_color": str(row["avatar_color"]),
            "avatar_eyes_large": bool(row["avatar_eyes_large"]),
            "engine_id": str(row["engine_id"]),
            "model_id": str(row["model_id"]),
            "thinking_level": str(row["thinking_level"]),
            "project_name": row["project_name"],
            "pinned": bool(row["pinned"]),
            "section_id": row["section_id"],
            "hidden": bool(row["hidden"]),
            "is_primary": bool(row["is_primary"]),
            "is_team_bot": bool(row["is_team_bot"]),
            "unread_count": int(row["unread_count"]),
            "needs_attention": bool(row["needs_attention"]),
            "status_state": str(row["status_state"]),
            "status_subtext": str(row["status_subtext"]),
            "computer_active": bool(row["computer_active"]),
            "timezone": str(row["timezone"]),
            "drafts_enabled": bool(row["drafts_enabled"]),
            "conversation_id": row["conversation_id"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_channel(row: sqlite3.Row) -> dict[str, Any]:
        raw_ids = _loads_json(row["bot_ids_json"], [])
        bot_ids = [str(item) for item in raw_ids] if isinstance(raw_ids, list) else []
        return {
            "id": str(row["id"]),
            "thread_id": str(row["thread_id"]),
            "name": str(row["name"]),
            "bot_ids": bot_ids,
            "pinned": bool(row["pinned"]),
            "section_id": row["section_id"],
            "hidden": bool(row["hidden"]),
            "unread_count": int(row["unread_count"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> dict[str, Any]:
        try:
            raw_meta = row["metadata_json"]
        except (IndexError, KeyError):
            raw_meta = "{}"
        parsed_meta = _loads_json(raw_meta, {})
        if not isinstance(parsed_meta, dict):
            parsed_meta = {}
        return {
            "id": str(row["id"]),
            "thread_id": str(row["thread_id"]),
            "sender_type": str(row["sender_type"]),
            "sender_bot_id": row["sender_bot_id"],
            "sender_name": str(row["sender_name"]),
            "content": str(row["content"]),
            "thinking_text": str(row["thinking_text"]),
            "reply_to_id": row["reply_to_id"],
            "mentions": _loads_json(row["mentions_json"], []),
            "attachments": _loads_json(row["attachments_json"], []),
            "tool_calls": _loads_json(row["tool_calls_json"], []),
            "artifacts": _loads_json(row["artifacts_json"], []),
            "reactions": _loads_json(row["reactions_json"], {}),
            "memory_diffs": _loads_json(row["memory_diffs_json"], []),
            "metadata": parsed_meta,
            "conversation_id": row["conversation_id"],
            "model_id": row["model_id"],
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
        }

    @staticmethod
    def _row_to_attachment(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "thread_id": row["thread_id"],
            "filename": str(row["filename"]),
            "mime_type": str(row["mime_type"]),
            "size_bytes": int(row["size_bytes"]),
            "created_at": str(row["created_at"]),
        }

    @staticmethod
    def _row_to_artifact(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "bot_id": str(row["bot_id"]),
            "thread_id": row["thread_id"],
            "message_id": row["message_id"],
            "type": str(row["type"]),
            "title": str(row["title"]),
            "content_md": str(row["content_md"]),
            "url": row["url"],
            "file_path": row["file_path"],
            "mime_type": str(row["mime_type"]),
            "size_bytes": int(row["size_bytes"]),
            "pinned": bool(row["pinned"]),
            "share_scope": str(row["share_scope"]),
            "version": int(row["version"]),
            "superseded_by_id": row["superseded_by_id"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_approval(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "bot_id": str(row["bot_id"]),
            "thread_id": str(row["thread_id"]),
            "kind": str(row["kind"]),
            "title": str(row["title"]),
            "target": str(row["target"]),
            "risk_banner": row["risk_banner"],
            "arguments": _loads_json(row["arguments_json"], {}),
            "status": str(row["status"]),
            "allow_always_allowed": bool(row["allow_always_allowed"]),
            "waiting_for_user": row["waiting_for_user"],
            "decision_by": row["decision_by"],
            "expires_at": row["expires_at"],
            "created_at": str(row["created_at"]),
            "resolved_at": row["resolved_at"],
        }

    @staticmethod
    def _row_to_draft(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "bot_id": str(row["bot_id"]),
            "thread_id": str(row["thread_id"]),
            "channel_type": str(row["channel_type"]),
            "fields": _loads_json(row["fields_json"], {}),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "resolved_at": row["resolved_at"],
        }

    @staticmethod
    def _row_to_secure_form(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "bot_id": str(row["bot_id"]),
            "thread_id": str(row["thread_id"]),
            "kind": str(row["kind"]),
            "domain": str(row["domain"]),
            "title": str(row["title"]),
            "fields": _loads_json(row["fields_json"], []),
            "allow_vault_save": bool(row["allow_vault_save"]),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "resolved_at": row["resolved_at"],
        }

    @staticmethod
    def _row_to_auto_review_rule(row: sqlite3.Row) -> dict[str, Any]:
        bucket = str(row["bucket"])
        text = str(row["rule_text"])
        return {
            "id": str(row["id"]),
            "bucket": bucket,
            "mode": bucket,
            "rule_type": bucket,
            "rule_text": text,
            "text": text,
            "locked_by_admin": False,
            "sort_order": int(row["sort_order"]),
            "created_at": str(row["created_at"]),
        }

    @staticmethod
    def _row_to_vault_secret_meta(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "bot_id": row["bot_id"],
            "name": str(row["name"]),
            "domain": str(row["domain"]),
            "kind": "credential",
            "username_hint": str(row["username_hint"]),
            "field_names": _loads_json(row["field_names_json"], []),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_routine(row: sqlite3.Row) -> dict[str, Any]:
        routine_id = str(row["id"])
        return {
            "id": routine_id,
            "bot_id": str(row["bot_id"]),
            "name": str(row["name"]),
            "instruction": str(row["instruction"]),
            "schedule_type": str(row["schedule_type"]),
            "cron_expr": row["cron_expr"],
            "timezone": str(row["timezone"]),
            "enabled": bool(row["enabled"]),
            "webhook_key": str(row["webhook_key"]),
            "webhook_url": f"/api/v1/webhooks/routines/{routine_id}",
            "visibility": str(row["visibility"]),
            "last_run_at": row["last_run_at"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_routine_run(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "routine_id": str(row["routine_id"]),
            "bot_id": str(row["bot_id"]),
            "trigger": str(row["trigger"]),
            "status": str(row["status"]),
            "summary": str(row["summary"]),
            "error": row["error"],
            "message_id": row["message_id"],
            "started_at": str(row["started_at"]),
            "finished_at": row["finished_at"],
        }

    @staticmethod
    def _row_to_skill(row: sqlite3.Row) -> dict[str, Any]:
        content_md = str(row["content_md"])
        return {
            "id": str(row["id"]),
            "bot_id": row["bot_id"],
            "name": str(row["name"]),
            "slug": str(row["slug"]),
            "description": str(row["description"]),
            "content_md": content_md,
            "instruction_md": content_md,
            "source": str(row["source"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _row_to_connected_app(row: sqlite3.Row) -> dict[str, Any]:
        enabled = bool(row["enabled"])
        cfg = _loads_json(row["config_json"], {})
        account_label = str(cfg.get("account_label") or "local-vm") if isinstance(cfg, dict) else ""
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "category": str(row["category"]),
            "description": str(row["description"]),
            "enabled": enabled,
            "connected": enabled,
            "account_label": account_label,
            "status": str(row["status"]),
            "config": cfg,
            "updated_at": str(row["updated_at"]),
        }

    # ------------------------------------------------------------------
    # Audit Chain & Computer VM / Teach State
    # ------------------------------------------------------------------

    def append_audit_event(
        self,
        *,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str | None = None,
        decision: str = "allow",
        detail: Mapping[str, Any] | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Append a SHA-256 hash-chained audit row atomically inside write_tx()."""
        if conn is not None:
            row = append_chained_audit_row(
                conn,
                actor=actor,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                decision=decision,
                detail=detail,
            )
            conn.execute(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('audit_head_seq', ?)",
                (str(row["seq"]),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('audit_head_hash', ?)",
                (str(row["entry_hash"]),),
            )
            return row

        with self.write_tx() as tx:
            row = append_chained_audit_row(
                tx,
                actor=actor,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                decision=decision,
                detail=detail,
            )
            tx.execute(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('audit_head_seq', ?)",
                (str(row["seq"]),),
            )
            tx.execute(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('audit_head_hash', ?)",
                (str(row["entry_hash"]),),
            )
            return row

    def list_audit_events(
        self,
        *,
        action: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 1000))
        clauses: list[str] = []
        params: list[Any] = []
        if action:
            clauses.append("action = ?")
            params.append(action)
        if entity_type:
            clauses.append("entity_type = ?")
            params.append(entity_type)
        if entity_id:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM workspace_audit_log
                {where}
                ORDER BY seq DESC
                LIMIT ?
                """,
                [*params, bounded],
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in reversed(rows):
            results.append(
                {
                    "seq": int(row["seq"]),
                    "prev_hash": str(row["prev_hash"]),
                    "entry_hash": str(row["entry_hash"]),
                    "actor": str(row["actor"]),
                    "action": str(row["action"]),
                    "entity_type": str(row["entity_type"]),
                    "entity_id": row["entity_id"],
                    "decision": str(row["decision"]),
                    "detail": _loads_json(str(row["detail_json"]), {}),
                    "created_at": str(row["created_at"]),
                }
            )
        return results

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify SHA-256 continuity, sequence contiguity, and payload integrity."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM workspace_audit_log ORDER BY seq ASC"
            ).fetchall()
            head_seq_row = self._conn.execute(
                "SELECT value FROM kv_meta WHERE key = 'audit_head_seq'"
            ).fetchone()
            head_hash_row = self._conn.execute(
                "SELECT value FROM kv_meta WHERE key = 'audit_head_hash'"
            ).fetchone()
            expected_count: int | None = None
            if head_seq_row is not None:
                with contextlib.suppress(ValueError):
                    kv_seq = int(str(head_seq_row["value"]))
                    if kv_seq > 0:
                        expected_count = kv_seq
            expected_head_hash = (
                str(head_hash_row["value"]) if head_hash_row is not None else None
            )
            return verify_chain(
                rows,
                expected_count=expected_count,
                expected_head_hash=expected_head_hash,
            )

    @staticmethod
    def _row_to_computer_vm(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "vm_id": str(row["vm_id"]),
            "control_owner": str(row["control_owner"]),
            "lease_id": row["lease_id"],
            "lease_owner": row["lease_owner"],
            "lease_expires_at": row["lease_expires_at"],
            "active_url": str(row["active_url"]),
            "active_tab_title": str(row["active_tab_title"]),
            "active_step_summary": row["active_step_summary"],
            "display_mode": str(row["display_mode"]),
            "viewport_width": int(row["viewport_width"]),
            "viewport_height": int(row["viewport_height"]),
            "is_teaching_task": bool(row["is_teaching_task"]),
            "teach_name": row["teach_name"],
            "teach_bot_id": row["teach_bot_id"],
            "teach_thread_id": row["teach_thread_id"],
            "teach_started_at": row["teach_started_at"],
            "updated_at": str(row["updated_at"]),
        }

    def save_computer_vm(self, vm_id: str, state: Mapping[str, Any]) -> dict[str, Any]:
        """Persist or update ComputerGateway VM state atomically."""
        cleaned_id = vm_id.strip()
        if not cleaned_id:
            raise StoreValidationError("vm_id must not be empty.")
        now = utc_iso_now()
        safe_url = str(scrub_v1_payload(str(state.get("active_url", ""))))
        safe_title = str(scrub_v1_payload(str(state.get("active_tab_title", ""))))
        raw_summary = state.get("active_step_summary")
        safe_summary = (
            str(scrub_v1_payload(str(raw_summary))) if raw_summary is not None else None
        )
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO computer_vms (
                    vm_id, control_owner, lease_id, lease_owner, lease_expires_at,
                    active_url, active_tab_title, active_step_summary, display_mode,
                    viewport_width, viewport_height, is_teaching_task, teach_name,
                    teach_bot_id, teach_thread_id, teach_started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vm_id) DO UPDATE SET
                    control_owner = excluded.control_owner,
                    lease_id = excluded.lease_id,
                    lease_owner = excluded.lease_owner,
                    lease_expires_at = excluded.lease_expires_at,
                    active_url = excluded.active_url,
                    active_tab_title = excluded.active_tab_title,
                    active_step_summary = excluded.active_step_summary,
                    display_mode = excluded.display_mode,
                    viewport_width = excluded.viewport_width,
                    viewport_height = excluded.viewport_height,
                    is_teaching_task = excluded.is_teaching_task,
                    teach_name = excluded.teach_name,
                    teach_bot_id = excluded.teach_bot_id,
                    teach_thread_id = excluded.teach_thread_id,
                    teach_started_at = excluded.teach_started_at,
                    updated_at = excluded.updated_at
                """,
                (
                    cleaned_id,
                    str(state.get("control_owner", "agent")),
                    state.get("lease_id"),
                    state.get("lease_owner"),
                    state.get("lease_expires_at"),
                    safe_url,
                    safe_title,
                    safe_summary,
                    str(state.get("display_mode", "vnc")),
                    int(state.get("viewport_width", 1280)),
                    int(state.get("viewport_height", 800)),
                    int(bool(state.get("is_teaching_task", False))),
                    state.get("teach_name"),
                    state.get("teach_bot_id"),
                    state.get("teach_thread_id"),
                    state.get("teach_started_at"),
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM computer_vms WHERE vm_id = ?", (cleaned_id,)
            ).fetchone()
            assert row is not None
            return self._row_to_computer_vm(row)

    def get_computer_vm(self, vm_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM computer_vms WHERE vm_id = ?", (vm_id,)
            ).fetchone()
            return self._row_to_computer_vm(row) if row is not None else None

    def list_computer_vms(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM computer_vms ORDER BY vm_id ASC"
            ).fetchall()
            return [self._row_to_computer_vm(r) for r in rows]

    def save_teach_steps(
        self,
        vm_id: str,
        steps: list[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Replace recorded teach steps for vm_id atomically inside write_tx()."""
        cleaned_id = vm_id.strip()
        if not cleaned_id:
            raise StoreValidationError("vm_id must not be empty.")
        now = utc_iso_now()
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO computer_vms (vm_id, updated_at)
                VALUES (?, ?)
                """,
                (cleaned_id, now),
            )
            conn.execute("DELETE FROM teach_steps WHERE vm_id = ?", (cleaned_id,))
            for idx, step in enumerate(steps, start=1):
                step_idx = int(step.get("step_index", idx))
                action = str(step.get("action", "step"))
                desc = str(scrub_v1_payload(str(step.get("description", ""))))
                url = str(scrub_v1_payload(str(step.get("url", ""))))
                ts = str(step.get("ts") or now)
                conn.execute(
                    """
                    INSERT INTO teach_steps (vm_id, step_index, action, description, url, ts)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cleaned_id, step_idx, action, desc, url, ts),
                )
            return self.get_teach_steps(cleaned_id)

    def get_teach_steps(self, vm_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM teach_steps
                WHERE vm_id = ?
                ORDER BY step_index ASC, id ASC
                """,
                (vm_id,),
            ).fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "vm_id": str(r["vm_id"]),
                    "step_index": int(r["step_index"]),
                    "action": str(r["action"]),
                    "description": str(r["description"]),
                    "url": str(r["url"]),
                    "ts": str(r["ts"]),
                }
                for r in rows
            ]

    # ------------------------------------------------------------------
    # Roster, Sections, Bots, Channels
    # ------------------------------------------------------------------

    def count_roster_items(self) -> int:
        with self._lock:
            bots_n = int(self._conn.execute("SELECT COUNT(*) FROM bots").fetchone()[0])
            chns_n = int(self._conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0])
            return bots_n + chns_n

    def list_roster(self) -> dict[str, Any]:
        with self._lock:
            return {
                "bots": self.list_bots(),
                "sections": self.list_sections(),
                "channels": self.list_channels(),
            }

    def list_sections(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sections ORDER BY sort_order ASC, created_at ASC"
            ).fetchall()
            return [self._row_to_section(r) for r in rows]

    def get_section(self, section_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sections WHERE id = ?", (section_id,)
            ).fetchone()
            return self._row_to_section(row) if row is not None else None

    def create_section(self, name: str, sort_order: int = 0) -> dict[str, Any]:
        sec_id = f"sec_{uuid.uuid4().hex[:10]}"
        now = utc_iso_now()
        with self.write_tx() as conn:
            conn.execute(
                "INSERT INTO sections (id, name, sort_order, created_at) VALUES (?, ?, ?, ?)",
                (sec_id, name, sort_order, now),
            )
            created = self.get_section(sec_id)
            assert created is not None
            return created

    def update_section(self, section_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_section(section_id) is None:
                raise StoreNotFoundError(f"Section not found: {section_id}")
            allowed = {"name", "sort_order"}
            fields = {k: v for k, v in updates.items() if k in allowed and v is not None}
            if fields:
                set_clause = ", ".join(f"{k} = ?" for k in fields)
                conn.execute(
                    f"UPDATE sections SET {set_clause} WHERE id = ?",
                    (*fields.values(), section_id),
                )
            updated = self.get_section(section_id)
            assert updated is not None
            return updated

    def delete_section(self, section_id: str) -> bool:
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM sections WHERE id = ?", (section_id,))
            return cur.rowcount > 0

    def list_bots(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bots ORDER BY is_primary DESC, pinned DESC, created_at ASC"
            ).fetchall()
            return [self._row_to_bot(r) for r in rows]

    def get_bot(self, bot_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM bots WHERE id = ?", (bot_id,)).fetchone()
            return self._row_to_bot(row) if row is not None else None

    def get_bot_by_thread(self, thread_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM bots WHERE thread_id = ?", (thread_id,)
            ).fetchone()
            return self._row_to_bot(row) if row is not None else None

    def create_bot(self, data: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.count_roster_items() >= MAX_ROSTER_ITEMS:
                raise StoreValidationError(
                    f"Workspace limit reached: maximum {MAX_ROSTER_ITEMS} bots and channels."
                )
            section_id = data.get("section_id")
            if section_id is not None and self.get_section(str(section_id)) is None:
                raise StoreValidationError(f"Unknown section_id: {section_id}")

            bot_id = f"bot_{uuid.uuid4().hex[:10]}"
            thread_id = f"thr_{bot_id}"
            now = utc_iso_now()
            is_primary = bool(data.get("is_primary", False))
            if is_primary:
                conn.execute("UPDATE bots SET is_primary = 0")

            conn.execute(
                """
                INSERT INTO bots (
                    id, thread_id, name, role_prompt, about, avatar_shape, avatar_color,
                    avatar_eyes_large, engine_id, model_id, thinking_level, project_name,
                    pinned, section_id, hidden, is_primary, is_team_bot, unread_count,
                    needs_attention, status_state, status_subtext, computer_active,
                    timezone, drafts_enabled, conversation_id, created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, 0,
                    'idle', 'Ready', 0, ?, ?, NULL, ?, ?
                )
                """,
                (
                    bot_id,
                    thread_id,
                    str(data["name"]),
                    str(data.get("role_prompt", "")),
                    str(data.get("about", "")),
                    str(data.get("avatar_shape", "sparkle")),
                    str(data.get("avatar_color", "#7C3AED")),
                    int(bool(data.get("avatar_eyes_large", False))),
                    str(data.get("engine_id", "agy")),
                    str(data.get("model_id", "gemini-4-carbon-low")),
                    str(data.get("thinking_level", "medium")),
                    data.get("project_name"),
                    int(bool(data.get("pinned", False))),
                    section_id,
                    int(is_primary),
                    int(bool(data.get("is_team_bot", False))),
                    str(data.get("timezone", "UTC")),
                    int(bool(data.get("drafts_enabled", True))),
                    now,
                    now,
                ),
            )
            created = self.get_bot(bot_id)
            assert created is not None
            return created

    def update_bot(self, bot_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_bot(bot_id) is None:
                raise StoreNotFoundError(f"Bot not found: {bot_id}")
            sec_id = updates.get("section_id")
            if sec_id is not None and self.get_section(str(sec_id)) is None:
                raise StoreValidationError(f"Unknown section_id: {sec_id}")

            bool_cols = {
                "avatar_eyes_large",
                "pinned",
                "hidden",
                "is_primary",
                "is_team_bot",
                "needs_attention",
                "computer_active",
                "drafts_enabled",
            }
            allowed_cols = {
                "name",
                "role_prompt",
                "about",
                "avatar_shape",
                "avatar_color",
                "avatar_eyes_large",
                "engine_id",
                "model_id",
                "thinking_level",
                "project_name",
                "pinned",
                "section_id",
                "hidden",
                "is_primary",
                "is_team_bot",
                "unread_count",
                "needs_attention",
                "status_state",
                "status_subtext",
                "computer_active",
                "timezone",
                "drafts_enabled",
                "conversation_id",
            }
            non_nullable_cols = {
                "name",
                "role_prompt",
                "about",
                "avatar_shape",
                "avatar_color",
                "avatar_eyes_large",
                "engine_id",
                "model_id",
                "thinking_level",
                "pinned",
                "hidden",
                "is_primary",
                "is_team_bot",
                "unread_count",
                "needs_attention",
                "status_state",
                "status_subtext",
                "computer_active",
                "timezone",
                "drafts_enabled",
            }
            if updates.get("is_primary") is True:
                conn.execute("UPDATE bots SET is_primary = 0 WHERE id != ?", (bot_id,))

            cols: list[str] = []
            vals: list[Any] = []
            for key, value in updates.items():
                if key not in allowed_cols:
                    continue
                if value is None and key in non_nullable_cols:
                    raise StoreValidationError(f"Field '{key}' must not be null.")
                cols.append(f"{key} = ?")
                vals.append(int(bool(value)) if key in bool_cols else value)

            if cols:
                cols.append("updated_at = ?")
                vals.append(utc_iso_now())
                vals.append(bot_id)
                conn.execute(f"UPDATE bots SET {', '.join(cols)} WHERE id = ?", vals)

            updated = self.get_bot(bot_id)
            assert updated is not None
            return updated

    def delete_bot(self, bot_id: str) -> bool:
        with self.write_tx() as conn:
            bot = self.get_bot(bot_id)
            if bot is None:
                return False
            bot_thread = str(bot["thread_id"])
            conn.execute("DELETE FROM messages WHERE thread_id = ?", (bot_thread,))
            conn.execute(
                "DELETE FROM attachments WHERE bot_id = ? OR thread_id = ?",
                (bot_id, bot_thread),
            )
            conn.execute(
                "DELETE FROM artifacts WHERE bot_id = ? OR thread_id = ?",
                (bot_id, bot_thread),
            )
            conn.execute(
                "DELETE FROM approvals WHERE bot_id = ? OR thread_id = ?",
                (bot_id, bot_thread),
            )
            conn.execute(
                "DELETE FROM drafts WHERE bot_id = ? OR thread_id = ?",
                (bot_id, bot_thread),
            )
            conn.execute(
                "DELETE FROM secure_forms WHERE bot_id = ? OR thread_id = ?",
                (bot_id, bot_thread),
            )
            conn.execute("DELETE FROM vault_secrets WHERE bot_id = ?", (bot_id,))
            conn.execute("DELETE FROM skills WHERE bot_id = ?", (bot_id,))
            conn.execute("DELETE FROM routine_runs WHERE bot_id = ?", (bot_id,))
            conn.execute("DELETE FROM routines WHERE bot_id = ?", (bot_id,))
            conn.execute("DELETE FROM bots WHERE id = ?", (bot_id,))
            now = utc_iso_now()
            channel_rows = conn.execute("SELECT id, bot_ids_json FROM channels").fetchall()
            for ch_row in channel_rows:
                raw_ids = _loads_json(ch_row["bot_ids_json"], [])
                if not isinstance(raw_ids, list):
                    continue
                old_ids = [str(item) for item in raw_ids]
                new_ids = [item for item in old_ids if item != bot_id]
                if len(new_ids) != len(old_ids):
                    conn.execute(
                        "UPDATE channels SET bot_ids_json = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(new_ids), now, str(ch_row["id"])),
                    )
            self.append_audit_event(
                actor="operator",
                action="bot.delete",
                entity_type="bot",
                entity_id=bot_id,
                decision="allow",
                detail={"thread_id": bot_thread, "name": bot["name"]},
                conn=conn,
            )
            return True

    def list_channels(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM channels ORDER BY pinned DESC, created_at ASC"
            ).fetchall()
            return [self._row_to_channel(r) for r in rows]

    def get_channel(self, channel_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM channels WHERE id = ?", (channel_id,)
            ).fetchone()
            return self._row_to_channel(row) if row is not None else None

    def get_channel_by_thread(self, thread_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM channels WHERE thread_id = ?", (thread_id,)
            ).fetchone()
            return self._row_to_channel(row) if row is not None else None

    def _validate_channel_bot_ids(self, bot_ids: list[str]) -> list[str]:
        if len(bot_ids) < 2 or len(bot_ids) > 6:
            raise StoreValidationError("Channels require between 2 and 6 bots.")
        missing = [bid for bid in bot_ids if self.get_bot(bid) is None]
        if missing:
            raise StoreValidationError(f"Unknown bot_ids in channel: {', '.join(missing)}")
        return bot_ids

    def create_channel(self, data: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.count_roster_items() >= MAX_ROSTER_ITEMS:
                raise StoreValidationError(
                    f"Workspace limit reached: maximum {MAX_ROSTER_ITEMS} bots and channels."
                )
            bot_ids = self._validate_channel_bot_ids([str(b) for b in data["bot_ids"]])
            section_id = data.get("section_id")
            if section_id is not None and self.get_section(str(section_id)) is None:
                raise StoreValidationError(f"Unknown section_id: {section_id}")

            chn_id = f"chn_{uuid.uuid4().hex[:10]}"
            thread_id = f"thr_{chn_id}"
            now = utc_iso_now()
            conn.execute(
                """
                INSERT INTO channels (
                    id, thread_id, name, bot_ids_json, pinned, section_id,
                    hidden, unread_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    chn_id,
                    thread_id,
                    str(data["name"]),
                    json.dumps(bot_ids),
                    int(bool(data.get("pinned", False))),
                    section_id,
                    now,
                    now,
                ),
            )
            created = self.get_channel(chn_id)
            assert created is not None
            return created

    def update_channel(self, channel_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_channel(channel_id) is None:
                raise StoreNotFoundError(f"Channel not found: {channel_id}")
            sec_id = updates.get("section_id")
            if sec_id is not None and self.get_section(str(sec_id)) is None:
                raise StoreValidationError(f"Unknown section_id: {sec_id}")

            cols: list[str] = []
            vals: list[Any] = []
            if "name" in updates and updates["name"] is not None:
                cols.append("name = ?")
                vals.append(str(updates["name"]))
            if "bot_ids" in updates and updates["bot_ids"] is not None:
                valid_ids = self._validate_channel_bot_ids([str(b) for b in updates["bot_ids"]])
                cols.append("bot_ids_json = ?")
                vals.append(json.dumps(valid_ids))
            if "pinned" in updates and updates["pinned"] is not None:
                cols.append("pinned = ?")
                vals.append(int(bool(updates["pinned"])))
            if "section_id" in updates:
                cols.append("section_id = ?")
                vals.append(updates["section_id"])
            if "hidden" in updates and updates["hidden"] is not None:
                cols.append("hidden = ?")
                vals.append(int(bool(updates["hidden"])))
            if "unread_count" in updates and updates["unread_count"] is not None:
                cols.append("unread_count = ?")
                vals.append(int(updates["unread_count"]))

            if cols:
                cols.append("updated_at = ?")
                vals.append(utc_iso_now())
                vals.append(channel_id)
                conn.execute(f"UPDATE channels SET {', '.join(cols)} WHERE id = ?", vals)

            updated = self.get_channel(channel_id)
            assert updated is not None
            return updated

    def delete_channel(self, channel_id: str) -> bool:
        with self.write_tx() as conn:
            chn = self.get_channel(channel_id)
            if chn is None:
                return False
            chn_thread = str(chn["thread_id"])
            conn.execute("DELETE FROM messages WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM attachments WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM artifacts WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM approvals WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM drafts WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM secure_forms WHERE thread_id = ?", (chn_thread,))
            conn.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
            self.append_audit_event(
                actor="operator",
                action="channel.delete",
                entity_type="channel",
                entity_id=channel_id,
                decision="allow",
                detail={"thread_id": chn_thread, "name": chn["name"]},
                conn=conn,
            )
            return True

    def thread_exists(self, thread_id: str) -> bool:
        with self._lock:
            return (
                self.get_bot_by_thread(thread_id) is not None
                or self.get_channel_by_thread(thread_id) is not None
            )

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def get_message(self, message_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
            return self._row_to_message(row) if row is not None else None

    def list_thread_messages(
        self,
        thread_id: str,
        *,
        limit: int = 50,
        before_id: str | None = None,
        strict_before_id: bool = False,
    ) -> tuple[list[dict[str, Any]], bool]:
        bounded = max(1, min(limit, 200))
        cleaned_before = before_id.strip() if before_id else ""
        with self._lock:
            before_seq: int | None = None
            if cleaned_before:
                row = self._conn.execute(
                    "SELECT seq FROM messages WHERE id = ? AND thread_id = ?",
                    (cleaned_before, thread_id),
                ).fetchone()
                if row is None:
                    if strict_before_id:
                        raise StoreNotFoundError(f"Cursor message not found: {cleaned_before}")
                    return [], False
                before_seq = int(row["seq"])

            if before_seq is not None:
                rows = self._conn.execute(
                    """
                    SELECT * FROM messages
                    WHERE thread_id = ? AND seq < ?
                    ORDER BY seq DESC
                    LIMIT ?
                    """,
                    (thread_id, before_seq, bounded + 1),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM messages
                    WHERE thread_id = ?
                    ORDER BY seq DESC
                    LIMIT ?
                    """,
                    (thread_id, bounded + 1),
                ).fetchall()

            has_more = len(rows) > bounded
            selected = list(reversed(rows[:bounded]))
            return [self._row_to_message(r) for r in selected], has_more

    def _increment_thread_unread(self, conn: sqlite3.Connection, thread_id: str, now: str) -> None:
        conn.execute(
            "UPDATE bots SET unread_count = unread_count + 1, updated_at = ? WHERE thread_id = ?",
            (now, thread_id),
        )
        conn.execute(
            "UPDATE channels SET unread_count = unread_count + 1, updated_at = ? "
            "WHERE thread_id = ?",
            (now, thread_id),
        )

    def mark_thread_read(self, thread_id: str) -> dict[str, Any]:
        """Reset unread_count to 0 for the bot or channel owning thread_id."""
        now = utc_iso_now()
        with self.write_tx() as conn:
            bot = self.get_bot_by_thread(thread_id)
            if bot is not None:
                conn.execute(
                    "UPDATE bots SET unread_count = 0, updated_at = ? WHERE id = ?",
                    (now, bot["id"]),
                )
                return {
                    "thread_id": thread_id,
                    "unread_count": 0,
                    "kind": "bot",
                    "entity_id": bot["id"],
                }
            chn = self.get_channel_by_thread(thread_id)
            if chn is not None:
                conn.execute(
                    "UPDATE channels SET unread_count = 0, updated_at = ? WHERE id = ?",
                    (now, chn["id"]),
                )
                return {
                    "thread_id": thread_id,
                    "unread_count": 0,
                    "kind": "channel",
                    "entity_id": chn["id"],
                }
            raise StoreNotFoundError(f"Thread not found: {thread_id}")

    def create_message(
        self,
        *,
        thread_id: str,
        sender_type: str,
        sender_name: str,
        content: str,
        sender_bot_id: str | None = None,
        thinking_text: str = "",
        reply_to_id: str | None = None,
        mentions: list[str] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        attachment_ids: list[str] | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        artifacts: list[dict[str, Any]] | None = None,
        memory_diffs: list[dict[str, Any]] | None = None,
        metadata: Mapping[str, Any] | None = None,
        conversation_id: str | None = None,
        model_id: str | None = None,
        status: str = "done",
    ) -> dict[str, Any]:
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        safe_content = str(scrub_v1_payload(content))
        safe_thinking = str(scrub_v1_payload(thinking_text))
        safe_tools = scrub_v1_payload(tool_calls or [])
        safe_artifacts = scrub_v1_payload(artifacts or [])
        safe_diffs = scrub_v1_payload(memory_diffs or [])
        safe_metadata = scrub_v1_payload(dict(metadata) if isinstance(metadata, Mapping) else {})
        with self.write_tx() as conn:
            resolved_attachments: list[dict[str, Any]] = []
            seen_att_ids: set[str] = set()
            for att in attachments or []:
                if not isinstance(att, Mapping):
                    continue
                raw_id = att.get("id")
                att_id_str = str(raw_id).strip() if raw_id is not None else ""
                if att_id_str:
                    att_row = conn.execute(
                        "SELECT id, filename, mime_type, size_bytes FROM attachments WHERE id = ?",
                        (att_id_str,),
                    ).fetchone()
                    if att_row is None or att_id_str in seen_att_ids:
                        continue
                    seen_att_ids.add(att_id_str)
                    resolved_attachments.append(
                        {
                            "id": str(att_row["id"]),
                            "filename": str(att_row["filename"]),
                            "mime_type": str(att_row["mime_type"]),
                            "size_bytes": int(att_row["size_bytes"]),
                        }
                    )
                else:
                    resolved_attachments.append(dict(att))
            for req_att_id in attachment_ids or []:
                clean_att_id = str(req_att_id).strip()
                if not clean_att_id or clean_att_id in seen_att_ids:
                    continue
                att_row = conn.execute(
                    "SELECT id, filename, mime_type, size_bytes FROM attachments WHERE id = ?",
                    (clean_att_id,),
                ).fetchone()
                if att_row is not None:
                    seen_att_ids.add(clean_att_id)
                    resolved_attachments.append(
                        {
                            "id": str(att_row["id"]),
                            "filename": str(att_row["filename"]),
                            "mime_type": str(att_row["mime_type"]),
                            "size_bytes": int(att_row["size_bytes"]),
                        }
                    )
            conn.execute(
                """
                INSERT INTO messages (
                    id, thread_id, sender_type, sender_bot_id, sender_name,
                    content, thinking_text, reply_to_id, mentions_json,
                    attachments_json, tool_calls_json, artifacts_json,
                    reactions_json, memory_diffs_json, metadata_json,
                    conversation_id, model_id, status, created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    msg_id,
                    thread_id,
                    sender_type,
                    sender_bot_id,
                    sender_name,
                    safe_content,
                    safe_thinking,
                    reply_to_id,
                    json.dumps(mentions or []),
                    json.dumps(resolved_attachments),
                    json.dumps(safe_tools),
                    json.dumps(safe_artifacts),
                    json.dumps(safe_diffs),
                    json.dumps(safe_metadata),
                    conversation_id,
                    model_id,
                    status,
                    now,
                ),
            )
            if sender_type != "user" and status != "streaming":
                self._increment_thread_unread(conn, thread_id, now)
            created = self.get_message(msg_id)
            assert created is not None
            return created

    def update_message(self, message_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            existing = self.get_message(message_id)
            if existing is None:
                raise StoreNotFoundError(f"Message not found: {message_id}")
            cols: list[str] = []
            vals: list[Any] = []
            json_map = {
                "mentions": "mentions_json",
                "attachments": "attachments_json",
                "tool_calls": "tool_calls_json",
                "artifacts": "artifacts_json",
                "reactions": "reactions_json",
                "memory_diffs": "memory_diffs_json",
                "metadata": "metadata_json",
            }
            plain_cols = {"content", "thinking_text", "conversation_id", "model_id", "status"}
            for key, value in updates.items():
                if key in plain_cols:
                    cols.append(f"{key} = ?")
                    vals.append(
                        str(scrub_v1_payload(value))
                        if key in {"content", "thinking_text"} and isinstance(value, str)
                        else value
                    )
                elif key in json_map:
                    cols.append(f"{json_map[key]} = ?")
                    if key == "metadata":
                        if isinstance(value, str):
                            parsed_val = _loads_json(value, {})
                            norm_val: dict[str, Any] = (
                                dict(parsed_val) if isinstance(parsed_val, Mapping) else {}
                            )
                        elif isinstance(value, Mapping):
                            norm_val = dict(value)
                        else:
                            norm_val = {}
                        vals.append(json.dumps(scrub_v1_payload(norm_val)))
                    else:
                        vals.append(json.dumps(scrub_v1_payload(value)))
            if cols:
                vals.append(message_id)
                conn.execute(f"UPDATE messages SET {', '.join(cols)} WHERE id = ?", vals)
            if (
                existing["status"] == "streaming"
                and updates.get("status") == "done"
                and existing["sender_type"] != "user"
            ):
                self._increment_thread_unread(conn, str(existing["thread_id"]), utc_iso_now())
            updated = self.get_message(message_id)
            assert updated is not None
            return updated

    def mark_streaming_interrupted(self, thread_id: str) -> list[dict[str, Any]]:
        with self.write_tx() as conn:
            rows = conn.execute(
                "SELECT id FROM messages WHERE thread_id = ? AND status = 'streaming'",
                (thread_id,),
            ).fetchall()
            updated: list[dict[str, Any]] = []
            for row in rows:
                msg = self.update_message(str(row["id"]), {"status": "interrupted"})
                updated.append(msg)
            return updated

    def record_reaction(
        self,
        message_id: str,
        emoji: str,
        actor: str = "operator",
        *,
        action: str = "toggle",
    ) -> dict[str, Any]:
        del actor
        with self.write_tx():
            msg = self.get_message(message_id)
            if msg is None:
                raise StoreNotFoundError(f"Message not found: {message_id}")
            reactions: dict[str, int] = {
                str(k): int(v) for k, v in dict(msg.get("reactions", {})).items() if int(v) > 0
            }
            current = reactions.get(emoji, 0)
            if action == "add":
                reactions[emoji] = current + 1
            elif action == "remove":
                if current <= 1:
                    reactions.pop(emoji, None)
                else:
                    reactions[emoji] = current - 1
            else:
                if current > 0:
                    reactions.pop(emoji, None)
                else:
                    reactions[emoji] = 1
            return self.update_message(message_id, {"reactions": reactions})

    def apply_reaction(
        self,
        message_id: str,
        emoji: str,
        action: str = "toggle",
    ) -> dict[str, Any]:
        return self.record_reaction(message_id, emoji, actor="operator", action=action)

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    def create_attachment(
        self,
        att_id: str,
        *,
        thread_id: str | None,
        bot_id: str | None,
        filename: str,
        mime_type: str,
        size_bytes: int,
        storage_path: str,
    ) -> dict[str, Any]:
        now = utc_iso_now()
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO attachments (
                    id, thread_id, bot_id, filename, mime_type, size_bytes,
                    storage_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (att_id, thread_id, bot_id, filename, mime_type, size_bytes, storage_path, now),
            )
            row = conn.execute(
                "SELECT * FROM attachments WHERE id = ?", (att_id,)
            ).fetchone()
            assert row is not None
            return self._row_to_attachment(row)

    def get_attachment_record(self, attachment_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
            ).fetchone()
            if row is None:
                return None
            record = self._row_to_attachment(row)
            record["storage_path"] = str(row["storage_path"])
            return record

    def get_attachments_summary(self, attachment_ids: list[str]) -> list[dict[str, Any]]:
        if not attachment_ids:
            return []
        with self._lock:
            summaries: list[dict[str, Any]] = []
            for att_id in attachment_ids:
                row = self._conn.execute(
                    "SELECT * FROM attachments WHERE id = ?", (att_id,)
                ).fetchone()
                if row is not None:
                    summaries.append(
                        {
                            "id": str(row["id"]),
                            "filename": str(row["filename"]),
                            "mime_type": str(row["mime_type"]),
                            "size_bytes": int(row["size_bytes"]),
                        }
                    )
            return summaries

    # ------------------------------------------------------------------
    # Artifacts, Pages, and Library
    # ------------------------------------------------------------------

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
            return self._row_to_artifact(row) if row is not None else None

    def create_artifact(
        self,
        *,
        bot_id: str,
        artifact_type: str,
        title: str,
        content_md: str = "",
        thread_id: str | None = None,
        message_id: str | None = None,
        url: str | None = None,
        file_path: str | None = None,
        mime_type: str = "text/markdown",
        size_bytes: int | None = None,
        pinned: bool = False,
        share_scope: str = "private",
        version: int = 1,
    ) -> dict[str, Any]:
        art_id = f"art_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        safe_content = str(scrub_v1_payload(content_md))
        resolved_size = (
            size_bytes if size_bytes is not None else len(safe_content.encode("utf-8"))
        )
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    id, bot_id, thread_id, message_id, type, title, content_md,
                    url, file_path, mime_type, size_bytes, pinned, share_scope,
                    version, superseded_by_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    art_id,
                    bot_id,
                    thread_id,
                    message_id,
                    artifact_type,
                    title,
                    safe_content,
                    url,
                    file_path,
                    mime_type,
                    resolved_size,
                    int(pinned),
                    share_scope,
                    version,
                    now,
                    now,
                ),
            )
            created = self.get_artifact(art_id)
            assert created is not None
            return created

    def create_or_version_page(
        self,
        *,
        bot_id: str,
        title: str,
        content_md: str,
        thread_id: str | None = None,
        message_id: str | None = None,
        pinned: bool = False,
        share_scope: str = "private",
    ) -> tuple[dict[str, Any], str | None]:
        with self.write_tx() as conn:
            prev_row = conn.execute(
                """
                SELECT * FROM artifacts
                WHERE bot_id = ? AND type = 'page' AND LOWER(title) = LOWER(?)
                  AND superseded_by_id IS NULL
                ORDER BY version DESC, created_at DESC
                LIMIT 1
                """,
                (bot_id, title),
            ).fetchone()
            next_version = int(prev_row["version"]) + 1 if prev_row is not None else 1
            supersedes_msg_id: str | None = (
                str(prev_row["message_id"])
                if prev_row is not None and prev_row["message_id"]
                else None
            )
            new_art = self.create_artifact(
                bot_id=bot_id,
                artifact_type="page",
                title=title,
                content_md=content_md,
                thread_id=thread_id,
                message_id=message_id,
                mime_type="text/markdown",
                pinned=pinned or (bool(prev_row["pinned"]) if prev_row is not None else False),
                share_scope=share_scope,
                version=next_version,
            )
            if prev_row is not None:
                conn.execute(
                    "UPDATE artifacts SET superseded_by_id = ?, updated_at = ? WHERE id = ?",
                    (new_art["id"], utc_iso_now(), str(prev_row["id"])),
                )
            return new_art, supersedes_msg_id

    def update_page(self, page_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            existing = self.get_artifact(page_id)
            if existing is None or existing["type"] != "page":
                raise StoreNotFoundError(f"Page not found: {page_id}")
            cols: list[str] = []
            vals: list[Any] = []
            bump_version = False
            if "title" in updates and updates["title"] is not None:
                cols.append("title = ?")
                vals.append(str(updates["title"]))
            if "content_md" in updates and updates["content_md"] is not None:
                safe_md = str(scrub_v1_payload(str(updates["content_md"])))
                cols.append("content_md = ?")
                vals.append(safe_md)
                cols.append("size_bytes = ?")
                vals.append(len(safe_md.encode("utf-8")))
                bump_version = True
            if "pinned" in updates and updates["pinned"] is not None:
                cols.append("pinned = ?")
                vals.append(int(bool(updates["pinned"])))
            if "share_scope" in updates and updates["share_scope"] is not None:
                cols.append("share_scope = ?")
                vals.append(str(updates["share_scope"]))
            if bump_version:
                cols.append("version = ?")
                vals.append(int(existing["version"]) + 1)
            if cols:
                cols.append("updated_at = ?")
                vals.append(utc_iso_now())
                vals.append(page_id)
                conn.execute(f"UPDATE artifacts SET {', '.join(cols)} WHERE id = ?", vals)
            updated = self.get_artifact(page_id)
            assert updated is not None
            return updated

    def pin_artifact(self, artifact_id: str, pinned: bool) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_artifact(artifact_id) is None:
                raise StoreNotFoundError(f"Artifact not found: {artifact_id}")
            conn.execute(
                "UPDATE artifacts SET pinned = ?, updated_at = ? WHERE id = ?",
                (int(pinned), utc_iso_now(), artifact_id),
            )
            updated = self.get_artifact(artifact_id)
            assert updated is not None
            return updated

    def delete_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.write_tx() as conn:
            art = self.get_artifact(artifact_id)
            if art is None:
                return None
            conn.execute(
                "UPDATE artifacts SET superseded_by_id = NULL WHERE superseded_by_id = ?",
                (artifact_id,),
            )
            conn.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))

            like_art = f"%{_escape_like(artifact_id)}%"
            art_msg_rows = conn.execute(
                "SELECT id, artifacts_json FROM messages "
                "WHERE artifacts_json LIKE ? ESCAPE '\\'",
                (like_art,),
            ).fetchall()
            updated_message_ids: list[str] = []
            for mrow in art_msg_rows:
                parsed_arts = _loads_json(str(mrow["artifacts_json"]), [])
                if not isinstance(parsed_arts, list):
                    continue
                filtered_arts = [
                    item
                    for item in parsed_arts
                    if not (
                        (isinstance(item, Mapping) and str(item.get("id") or "") == artifact_id)
                        or (isinstance(item, str) and item == artifact_id)
                    )
                ]
                if len(filtered_arts) != len(parsed_arts):
                    conn.execute(
                        "UPDATE messages SET artifacts_json = ? WHERE id = ?",
                        (json.dumps(filtered_arts), str(mrow["id"])),
                    )
                    updated_message_ids.append(str(mrow["id"]))

            unreferenced_path: str | None = None
            url = str(art.get("url") or "")
            base_url = url.split("?", 1)[0].split("#", 1)[0].strip().rstrip("/")
            if base_url.startswith("/api/v1/attachments/"):
                att_id = base_url.rsplit("/", 1)[-1].strip()
                if att_id:
                    escaped_base = _escape_like(base_url)
                    other_refs = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM artifacts WHERE "
                            "url = ? OR url LIKE ? ESCAPE '\\' "
                            "OR url = ? OR url LIKE ? ESCAPE '\\' "
                            "OR url LIKE ? ESCAPE '\\'",
                            (
                                base_url,
                                f"{escaped_base}?%",
                                f"{base_url}/",
                                f"{escaped_base}/?%",
                                f"{escaped_base}#%",
                            ),
                        ).fetchone()[0]
                    )
                    bound_in_messages = False
                    if other_refs == 0:
                        like_pat = f"%{_escape_like(att_id)}%"
                        msg_rows = conn.execute(
                            "SELECT attachments_json FROM messages "
                            "WHERE attachments_json LIKE ? ESCAPE '\\'",
                            (like_pat,),
                        ).fetchall()
                        for mrow in msg_rows:
                            parsed_atts = _loads_json(mrow["attachments_json"], [])
                            if not isinstance(parsed_atts, list):
                                continue
                            for att_item in parsed_atts:
                                if (
                                    isinstance(att_item, Mapping)
                                    and str(att_item.get("id") or "") == att_id
                                ) or (isinstance(att_item, str) and att_item == att_id):
                                    bound_in_messages = True
                                    break
                            if bound_in_messages:
                                break
                    if other_refs == 0 and not bound_in_messages:
                        att_row = conn.execute(
                            "SELECT storage_path FROM attachments WHERE id = ?", (att_id,)
                        ).fetchone()
                        if att_row is not None:
                            storage_path = str(att_row["storage_path"])
                            conn.execute("DELETE FROM attachments WHERE id = ?", (att_id,))
                            path_refs = int(
                                conn.execute(
                                    "SELECT COUNT(*) FROM attachments WHERE storage_path = ?",
                                    (storage_path,),
                                ).fetchone()[0]
                            )
                            if path_refs == 0:
                                unreferenced_path = storage_path

            self.append_audit_event(
                actor="operator",
                action="artifact.delete",
                entity_type="artifact",
                entity_id=artifact_id,
                decision="allow",
                detail={"bot_id": art["bot_id"], "type": art["type"], "title": art["title"]},
                conn=conn,
            )
            return {
                "deleted": True,
                "artifact": art,
                "attachment_path": unreferenced_path,
                "updated_message_ids": updated_message_ids,
            }

    def list_bot_library(
        self,
        bot_id: str,
        *,
        artifact_type: str = "all",
        pinned_only: bool = False,
        query: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            clauses = ["bot_id = ?", "superseded_by_id IS NULL"]
            params: list[Any] = [bot_id]
            if artifact_type and artifact_type != "all":
                clauses.append("type = ?")
                params.append(artifact_type)
            if pinned_only:
                clauses.append("pinned = 1")
            cleaned_q = query.strip()
            if cleaned_q:
                like = f"%{_escape_like(cleaned_q)}%"
                clauses.append(
                    "(title LIKE ? ESCAPE '\\' OR content_md LIKE ? ESCAPE '\\' "
                    "OR url LIKE ? ESCAPE '\\' OR file_path LIKE ? ESCAPE '\\')"
                )
                params.extend([like, like, like, like])

            sql = f"SELECT * FROM artifacts WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC"
            rows = self._conn.execute(sql, params).fetchall()
            items = [self._row_to_artifact(r) for r in rows]

        now_date = datetime.now(tz=UTC).date()
        grouped: dict[str, list[dict[str, Any]]] = {
            "pinned": [],
            "today": [],
            "this_week": [],
            "older": [],
        }
        for item in items:
            if item["pinned"]:
                grouped["pinned"].append(item)
                continue
            dt = _parse_iso(str(item["updated_at"])) or _parse_iso(str(item["created_at"]))
            if dt is None:
                grouped["older"].append(item)
                continue
            delta_days = (now_date - dt.date()).days
            if delta_days <= 0:
                grouped["today"].append(item)
            elif delta_days <= 7:
                grouped["this_week"].append(item)
            else:
                grouped["older"].append(item)
        return {"items": items, "grouped": grouped}

    # ------------------------------------------------------------------
    # Approvals, Drafts, Secure Forms, Idempotency
    # ------------------------------------------------------------------

    def _check_and_record_idempotency(self, scope: str, idem_key: str | None) -> None:
        if not idem_key or not idem_key.strip():
            return
        cleaned = idem_key.strip()
        existing = self._conn.execute(
            "SELECT 1 FROM idempotency_keys WHERE scope = ? AND idem_key = ?",
            (scope, cleaned),
        ).fetchone()
        if existing is not None:
            raise StoreConflictError(f"Duplicate Idempotency-Key for {scope}: {cleaned}")
        self._conn.execute(
            "INSERT INTO idempotency_keys (scope, idem_key, created_at) VALUES (?, ?, ?)",
            (scope, cleaned, utc_iso_now()),
        )

    def create_approval(
        self,
        *,
        bot_id: str,
        thread_id: str,
        kind: str = "standard",
        title: str,
        target: str = "vm:default",
        risk_banner: str | None = None,
        arguments: dict[str, Any] | None = None,
        allow_always_allowed: bool = True,
        waiting_for_user: str | None = None,
        expires_in_minutes: int | None = 30,
        pending_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        apr_id = f"apr_{uuid.uuid4().hex[:12]}"
        now_dt = datetime.now(tz=UTC)
        now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_at: str | None = None
        if expires_in_minutes is not None:
            expires_at = (now_dt + timedelta(minutes=expires_in_minutes)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        safe_args = scrub_v1_payload(arguments or {})
        safe_pending = (
            scrub_v1_payload(pending_context) if pending_context is not None else None
        )
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO approvals (
                    id, bot_id, thread_id, kind, title, target, risk_banner,
                    arguments_json, status, allow_always_allowed, waiting_for_user,
                    decision_by, expires_at, created_at, resolved_at, pending_context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL, ?, ?, NULL, ?)
                """,
                (
                    apr_id,
                    bot_id,
                    thread_id,
                    kind,
                    title,
                    target,
                    risk_banner,
                    json.dumps(safe_args),
                    int(allow_always_allowed),
                    waiting_for_user,
                    expires_at,
                    now,
                    json.dumps(safe_pending) if safe_pending is not None else None,
                ),
            )
            self.append_audit_event(
                actor="agent",
                action="approval.create",
                entity_type="approval",
                entity_id=apr_id,
                decision="pending",
                detail={"bot_id": bot_id, "kind": kind, "target": target},
                conn=conn,
            )
            created = self.get_approval(apr_id)
            assert created is not None
            return created

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            return self._row_to_approval(row) if row is not None else None

    def get_approval_pending_context(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT pending_context_json FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if row is None or not row["pending_context_json"]:
                return None
            parsed = _loads_json(row["pending_context_json"], None)
            return parsed if isinstance(parsed, dict) else None

    def expire_stale_approvals(self) -> list[dict[str, Any]]:
        now_dt = datetime.now(tz=UTC)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        expired: list[dict[str, Any]] = []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM approvals
                WHERE status = 'pending' AND expires_at IS NOT NULL
                """
            ).fetchall()
            to_expire = [
                str(row["id"])
                for row in rows
                if (exp_dt := _parse_iso(str(row["expires_at"]))) is not None and exp_dt <= now_dt
            ]
            if not to_expire:
                return []
            with self.write_tx() as conn:
                for apr_id in to_expire:
                    conn.execute(
                        "UPDATE approvals SET status = 'expired', resolved_at = ? "
                        "WHERE id = ? AND status = 'pending'",
                        (now_iso, apr_id),
                    )
                    updated = self.get_approval(apr_id)
                    if updated is not None and updated["status"] == "expired":
                        expired.append(updated)
        return expired

    def list_thread_approvals(self, thread_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self.expire_stale_approvals()
            rows = self._conn.execute(
                "SELECT * FROM approvals WHERE thread_id = ? ORDER BY created_at ASC",
                (thread_id,),
            ).fetchall()
            return [self._row_to_approval(r) for r in rows]

    def count_pending_approvals_for_bot(self, bot_id: str) -> int:
        with self._lock:
            self.expire_stale_approvals()
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM approvals WHERE bot_id = ? AND status = 'pending'",
                    (bot_id,),
                ).fetchone()[0]
            )

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        decision_by: str = "operator",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        decision_status_map = {
            "allow_once": "allowed_once",
            "always_allow": "allowed_always",
            "deny": "denied",
            "skip": "skipped",
        }
        if decision not in decision_status_map:
            raise StoreValidationError(f"Unsupported approval decision: {decision}")

        with self.write_tx() as conn:
            self.expire_stale_approvals()
            existing = self.get_approval(approval_id)
            if existing is None:
                raise StoreNotFoundError(f"Approval not found: {approval_id}")
            if existing["status"] != "pending":
                raise StoreConflictError(
                    f"Approval {approval_id} already resolved with status '{existing['status']}'."
                )
            if decision == "always_allow" and not existing["allow_always_allowed"]:
                raise StoreConflictError(
                    f"Approval {approval_id} does not allow 'always_allow'."
                )
            self._check_and_record_idempotency("approval_resolve", idempotency_key)

            new_status = decision_status_map[decision]
            now = utc_iso_now()
            conn.execute(
                """
                UPDATE approvals
                SET status = ?, decision_by = ?, resolved_at = ?
                WHERE id = ?
                """,
                (new_status, decision_by, now, approval_id),
            )
            self.append_audit_event(
                actor=decision_by,
                action="approval.resolve",
                entity_type="approval",
                entity_id=approval_id,
                decision=new_status,
                detail={"bot_id": existing["bot_id"], "decision": decision},
                conn=conn,
            )
            updated = self.get_approval(approval_id)
            assert updated is not None
            return updated

    def create_draft(
        self,
        *,
        bot_id: str,
        thread_id: str,
        channel_type: str = "email",
        fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        drf_id = f"drf_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        safe_fields = scrub_v1_payload(fields or {})
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO drafts (
                    id, bot_id, thread_id, channel_type, fields_json,
                    status, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL)
                """,
                (drf_id, bot_id, thread_id, channel_type, json.dumps(safe_fields), now),
            )
            created = self.get_draft(drf_id)
            assert created is not None
            return created

    def get_draft(self, draft_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM drafts WHERE id = ?", (draft_id,)).fetchone()
            return self._row_to_draft(row) if row is not None else None

    def list_thread_drafts(self, thread_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM drafts WHERE thread_id = ? ORDER BY created_at ASC",
                (thread_id,),
            ).fetchall()
            return [self._row_to_draft(r) for r in rows]

    def resolve_draft(
        self,
        draft_id: str,
        action: str,
        *,
        fields: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if action not in {"send", "discard", "update"}:
            raise StoreValidationError(f"Unsupported draft action: {action}")
        if fields is not None and not isinstance(fields, dict):
            raise StoreValidationError("Draft fields must be a mapping.")

        with self.write_tx() as conn:
            existing = self.get_draft(draft_id)
            if existing is None:
                raise StoreNotFoundError(f"Draft not found: {draft_id}")
            if existing["status"] != "pending":
                raise StoreConflictError(
                    f"Draft {draft_id} already resolved with status '{existing['status']}'."
                )
            self._check_and_record_idempotency("draft_resolve", idempotency_key)

            merged_fields = dict(existing["fields"])
            if fields is not None:
                merged_fields.update(scrub_v1_payload(fields))

            if action == "update":
                conn.execute(
                    "UPDATE drafts SET fields_json = ? WHERE id = ?",
                    (json.dumps(merged_fields), draft_id),
                )
            else:
                new_status = "sent" if action == "send" else "discarded"
                conn.execute(
                    """
                    UPDATE drafts
                    SET fields_json = ?, status = ?, resolved_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(merged_fields), new_status, utc_iso_now(), draft_id),
                )

            self.append_audit_event(
                actor="operator",
                action="draft.resolve",
                entity_type="draft",
                entity_id=draft_id,
                decision=action,
                detail={
                    "bot_id": existing["bot_id"],
                    "channel_type": existing["channel_type"],
                },
                conn=conn,
            )
            updated = self.get_draft(draft_id)
            assert updated is not None
            return updated

    def create_secure_form(
        self,
        *,
        bot_id: str,
        thread_id: str,
        kind: str = "form",
        domain: str = "",
        title: str,
        fields: list[dict[str, Any]],
        allow_vault_save: bool = True,
    ) -> dict[str, Any]:
        sfm_id = f"sfm_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        safe_fields = [
            {
                "name": str(item["name"]),
                "label": str(item["label"]),
                "secret": bool(item.get("secret", False)),
            }
            for item in fields
        ]
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO secure_forms (
                    id, bot_id, thread_id, kind, domain, title, fields_json,
                    allow_vault_save, status, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)
                """,
                (
                    sfm_id,
                    bot_id,
                    thread_id,
                    kind,
                    domain,
                    title,
                    json.dumps(safe_fields),
                    int(allow_vault_save),
                    now,
                ),
            )
            created = self.get_secure_form(sfm_id)
            assert created is not None
            return created

    def get_secure_form(self, form_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM secure_forms WHERE id = ?", (form_id,)
            ).fetchone()
            return self._row_to_secure_form(row) if row is not None else None

    def list_thread_secure_forms(self, thread_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM secure_forms WHERE thread_id = ? ORDER BY created_at ASC",
                (thread_id,),
            ).fetchall()
            return [self._row_to_secure_form(r) for r in rows]

    def resolve_secure_form(
        self,
        form_id: str,
        *,
        status: str = "submitted",
    ) -> dict[str, Any]:
        with self.write_tx() as conn:
            existing = self.get_secure_form(form_id)
            if existing is None:
                raise StoreNotFoundError(f"Secure form not found: {form_id}")
            conn.execute(
                "UPDATE secure_forms SET status = ?, resolved_at = ? WHERE id = ?",
                (status, utc_iso_now(), form_id),
            )
            self.append_audit_event(
                actor="operator",
                action="secure_form.resolve",
                entity_type="secure_form",
                entity_id=form_id,
                decision=status,
                detail={"bot_id": existing["bot_id"], "domain": existing["domain"]},
                conn=conn,
            )
            updated = self.get_secure_form(form_id)
            assert updated is not None
            return updated

    # ------------------------------------------------------------------
    # Auto-Review Rules
    # ------------------------------------------------------------------

    def list_auto_review_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM auto_review_rules
                ORDER BY bucket ASC, sort_order ASC, created_at ASC
                """
            ).fetchall()
            return [self._row_to_auto_review_rule(r) for r in rows]

    def replace_auto_review_rules(
        self,
        rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        normalized_rules: list[tuple[str, str, str, int]] = []
        allow_count = 0
        ask_count = 0
        seen_ids: set[str] = set()
        for idx, item in enumerate(rules):
            if not isinstance(item, Mapping):
                raise StoreValidationError("Each auto-review rule must be a mapping.")
            bucket = str(item.get("bucket") or item.get("mode") or item.get("rule_type") or "")
            if bucket not in {"allow_auto", "ask_first"}:
                raise StoreValidationError(f"Unsupported auto-review bucket: {bucket!r}")
            raw_text = (
                item.get("rule_text") if item.get("rule_text") is not None else item.get("text")
            )
            rule_text = str(raw_text or "").strip()
            if not rule_text or len(rule_text) > MAX_AUTO_REVIEW_RULE_LEN:
                raise StoreValidationError(
                    f"Auto-review rule must be 1..{MAX_AUTO_REVIEW_RULE_LEN} chars."
                )
            if bucket == "allow_auto":
                allow_count += 1
            else:
                ask_count += 1
            raw_id = item.get("id")
            cleaned_id = str(raw_id).strip() if raw_id is not None else ""
            if cleaned_id:
                if cleaned_id in seen_ids:
                    raise StoreValidationError(f"Duplicate auto-review rule id: {cleaned_id}")
                seen_ids.add(cleaned_id)
                rule_id = cleaned_id
            else:
                rule_id = f"arr_{uuid.uuid4().hex[:10]}"
            normalized_rules.append((rule_id, bucket, rule_text, idx))

        if allow_count > MAX_AUTO_REVIEW_RULES_PER_BUCKET:
            raise StoreValidationError(
                f"At most {MAX_AUTO_REVIEW_RULES_PER_BUCKET} allow_auto rules allowed."
            )
        if ask_count > MAX_AUTO_REVIEW_RULES_PER_BUCKET:
            raise StoreValidationError(
                f"At most {MAX_AUTO_REVIEW_RULES_PER_BUCKET} ask_first rules allowed."
            )

        now = utc_iso_now()
        with self.write_tx() as conn:
            conn.execute("DELETE FROM auto_review_rules")
            for rule_id, bucket, rule_text, idx in normalized_rules:
                conn.execute(
                    """
                    INSERT INTO auto_review_rules (id, bucket, rule_text, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (rule_id, bucket, rule_text, idx, now),
                )
            self.append_audit_event(
                actor="operator",
                action="auto_review.replace",
                entity_type="auto_review_rule",
                entity_id=None,
                decision="allow",
                detail={"count": len(normalized_rules)},
                conn=conn,
            )
            return self.list_auto_review_rules()

    def add_auto_review_rule(self, bucket: str, rule_text: str) -> dict[str, Any] | None:
        cleaned = rule_text.strip()[:MAX_AUTO_REVIEW_RULE_LEN]
        if not cleaned:
            return None
        with self.write_tx() as conn:
            existing = self.list_auto_review_rules()
            bucket_rules = [r for r in existing if r["bucket"] == bucket]
            for r in bucket_rules:
                if str(r["rule_text"]).strip().lower() == cleaned.lower():
                    return r
            if len(bucket_rules) >= MAX_AUTO_REVIEW_RULES_PER_BUCKET:
                return None
            rule_id = f"arr_{uuid.uuid4().hex[:10]}"
            now = utc_iso_now()
            conn.execute(
                """
                INSERT INTO auto_review_rules (id, bucket, rule_text, sort_order, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (rule_id, bucket, cleaned, len(bucket_rules), now),
            )
            self.append_audit_event(
                actor="operator",
                action="auto_review.add",
                entity_type="auto_review_rule",
                entity_id=rule_id,
                decision="allow",
                detail={"bucket": bucket},
                conn=conn,
            )
            row = conn.execute(
                "SELECT * FROM auto_review_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            return self._row_to_auto_review_rule(row) if row is not None else None

    # ------------------------------------------------------------------
    # Vault Secrets (Encrypted at rest, metadata-only public API)
    # ------------------------------------------------------------------

    def list_vault_secrets(self, bot_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if bot_id:
                rows = self._conn.execute(
                    """
                    SELECT * FROM vault_secrets
                    WHERE bot_id IS NULL OR bot_id = ?
                    ORDER BY updated_at DESC
                    """,
                    (bot_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM vault_secrets ORDER BY updated_at DESC"
                ).fetchall()
            return [self._row_to_vault_secret_meta(r) for r in rows]

    def create_vault_secret(
        self,
        *,
        bot_id: str | None,
        name: str,
        domain: str = "",
        username_hint: str = "",
        fields: dict[str, str],
    ) -> dict[str, Any]:
        sec_id = f"vlt_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        encrypted = self._encrypt_vault_payload(fields)
        field_names = sorted(fields.keys())
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO vault_secrets (
                    id, bot_id, name, domain, username_hint, field_names_json,
                    encrypted_payload, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sec_id,
                    bot_id,
                    name,
                    domain,
                    username_hint,
                    json.dumps(field_names),
                    encrypted,
                    now,
                    now,
                ),
            )
            self.append_audit_event(
                actor="operator",
                action="vault.create",
                entity_type="vault_secret",
                entity_id=sec_id,
                decision="allow",
                detail={"bot_id": bot_id, "domain": domain, "field_names": field_names},
                conn=conn,
            )
            row = conn.execute(
                "SELECT * FROM vault_secrets WHERE id = ?", (sec_id,)
            ).fetchone()
            assert row is not None
            return self._row_to_vault_secret_meta(row)

    def decrypt_vault_secret(self, secret_id: str) -> dict[str, str] | None:
        """Internal server-side decryption for secure browser auto-fill only."""
        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT encrypted_payload FROM vault_secrets WHERE id = ?", (secret_id,)
            ).fetchone()
            if row is None:
                self.append_audit_event(
                    actor="operator",
                    action="vault.decrypt",
                    entity_type="vault_secret",
                    entity_id=secret_id,
                    decision="not_found",
                    detail={"field_count": 0},
                    conn=conn,
                )
                return None
            decrypted = self._decrypt_vault_payload(str(row["encrypted_payload"]))
            self.append_audit_event(
                actor="operator",
                action="vault.decrypt",
                entity_type="vault_secret",
                entity_id=secret_id,
                decision="allow",
                detail={"field_count": len(decrypted)},
                conn=conn,
            )
            return decrypted

    def delete_vault_secret(self, secret_id: str) -> bool:
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM vault_secrets WHERE id = ?", (secret_id,))
            deleted = cur.rowcount > 0
            self.append_audit_event(
                actor="operator",
                action="vault.delete",
                entity_type="vault_secret",
                entity_id=secret_id,
                decision="allow" if deleted else "not_found",
                detail={},
                conn=conn,
            )
            return deleted

    # ------------------------------------------------------------------
    # Routines & Routine Runs
    # ------------------------------------------------------------------

    def list_routines(
        self,
        bot_id: str | None = None,
        *,
        enabled_only: bool = False,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if bot_id is not None:
                clauses.append("bot_id = ?")
                params.append(bot_id)
            if enabled_only:
                clauses.append("enabled = 1")
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self._conn.execute(
                f"SELECT * FROM routines {where} ORDER BY created_at ASC", params
            ).fetchall()
            return [self._row_to_routine(r) for r in rows]

    def get_routine(self, routine_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM routines WHERE id = ?", (routine_id,)
            ).fetchone()
            return self._row_to_routine(row) if row is not None else None

    def create_routine(self, bot_id: str, data: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_bot(bot_id) is None:
                raise StoreNotFoundError(f"Bot not found: {bot_id}")
            existing_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM routines WHERE bot_id = ?", (bot_id,)
                ).fetchone()[0]
            )
            if existing_count >= MAX_ROUTINES_PER_BOT:
                raise StoreValidationError(
                    f"Maximum {MAX_ROUTINES_PER_BOT} routines allowed per bot."
                )
            rtn_id = f"rtn_{uuid.uuid4().hex[:10]}"
            now = utc_iso_now()
            webhook_key = f"whk_{secrets.token_hex(16)}"
            conn.execute(
                """
                INSERT INTO routines (
                    id, bot_id, name, instruction, schedule_type, cron_expr, timezone,
                    enabled, webhook_key, visibility, last_run_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    rtn_id,
                    bot_id,
                    str(data["name"]),
                    str(data["instruction"]),
                    str(data.get("schedule_type", "cron")),
                    data.get("cron_expr"),
                    str(data.get("timezone", "UTC")),
                    int(bool(data.get("enabled", True))),
                    webhook_key,
                    str(data.get("visibility", "only_me")),
                    now,
                    now,
                ),
            )
            created = self.get_routine(rtn_id)
            assert created is not None
            return created

    def update_routine(self, routine_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            if self.get_routine(routine_id) is None:
                raise StoreNotFoundError(f"Routine not found: {routine_id}")
            cols: list[str] = []
            vals: list[Any] = []
            non_nullable_routine_fields = {
                "name",
                "instruction",
                "schedule_type",
                "timezone",
                "visibility",
            }
            routine_fields = (
                "name",
                "instruction",
                "schedule_type",
                "cron_expr",
                "timezone",
                "visibility",
            )
            for key in routine_fields:
                if key in updates:
                    val = updates[key]
                    if val is None and key in non_nullable_routine_fields:
                        raise StoreValidationError(f"Field '{key}' must not be null.")
                    cols.append(f"{key} = ?")
                    vals.append(val)
            if "enabled" in updates:
                if updates["enabled"] is None:
                    raise StoreValidationError("Field 'enabled' must not be null.")
                cols.append("enabled = ?")
                vals.append(int(bool(updates["enabled"])))
            if updates.get("regenerate_webhook_key") is True:
                cols.append("webhook_key = ?")
                vals.append(f"whk_{secrets.token_hex(16)}")
            if "last_run_at" in updates:
                cols.append("last_run_at = ?")
                vals.append(updates["last_run_at"])
            if cols:
                cols.append("updated_at = ?")
                vals.append(utc_iso_now())
                vals.append(routine_id)
                conn.execute(f"UPDATE routines SET {', '.join(cols)} WHERE id = ?", vals)
            updated = self.get_routine(routine_id)
            assert updated is not None
            return updated

    def delete_routine(self, routine_id: str) -> bool:
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM routines WHERE id = ?", (routine_id,))
            return cur.rowcount > 0

    def create_routine_run(
        self,
        routine_id: str,
        bot_id: str,
        *,
        trigger: str = "manual",
    ) -> dict[str, Any]:
        run_id = f"rrn_{uuid.uuid4().hex[:12]}"
        now = utc_iso_now()
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO routine_runs (
                    id, routine_id, bot_id, trigger, status, summary, error,
                    message_id, started_at, finished_at
                ) VALUES (?, ?, ?, ?, 'running', '', NULL, NULL, ?, NULL)
                """,
                (run_id, routine_id, bot_id, trigger, now),
            )
            # Prune runs beyond latest 20 for this routine
            conn.execute(
                """
                DELETE FROM routine_runs
                WHERE routine_id = ? AND id NOT IN (
                    SELECT id FROM routine_runs
                    WHERE routine_id = ?
                    ORDER BY started_at DESC, rowid DESC
                    LIMIT 20
                )
                """,
                (routine_id, routine_id),
            )
            row = conn.execute(
                "SELECT * FROM routine_runs WHERE id = ?", (run_id,)
            ).fetchone()
            assert row is not None
            return self._row_to_routine_run(row)

    def get_routine_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM routine_runs WHERE id = ?", (run_id,)
            ).fetchone()
            return self._row_to_routine_run(row) if row is not None else None

    def update_routine_run(self, run_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            cols: list[str] = []
            vals: list[Any] = []
            for key in ("status", "summary", "error", "message_id", "finished_at"):
                if key in updates:
                    val = updates[key]
                    if key in {"summary", "error"} and isinstance(val, str):
                        val = str(scrub_v1_payload(val))
                    cols.append(f"{key} = ?")
                    vals.append(val)
            if cols:
                vals.append(run_id)
                conn.execute(
                    f"UPDATE routine_runs SET {', '.join(cols)} WHERE id = ?", vals
                )
            row = conn.execute(
                "SELECT * FROM routine_runs WHERE id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise StoreNotFoundError(f"Routine run not found: {run_id}")
            return self._row_to_routine_run(row)

    def list_routine_runs(self, routine_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 20))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM routine_runs
                WHERE routine_id = ?
                ORDER BY started_at DESC, rowid DESC
                LIMIT ?
                """,
                (routine_id, bounded),
            ).fetchall()
            return [self._row_to_routine_run(r) for r in rows]

    # ------------------------------------------------------------------
    # Skills
    # ------------------------------------------------------------------

    def list_skills(self, bot_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if bot_id:
                rows = self._conn.execute(
                    """
                    SELECT * FROM skills
                    WHERE bot_id IS NULL OR bot_id = ?
                    ORDER BY created_at DESC
                    """,
                    (bot_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM skills ORDER BY created_at DESC"
                ).fetchall()
            return [self._row_to_skill(r) for r in rows]

    def create_skill(self, data: dict[str, Any]) -> dict[str, Any]:
        skl_id = f"skl_{uuid.uuid4().hex[:10]}"
        now = utc_iso_now()
        name = str(data["name"]).strip()
        slug = _slugify(name)
        with self.write_tx() as conn:
            conn.execute(
                """
                INSERT INTO skills (
                    id, bot_id, name, slug, description, content_md,
                    source, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    skl_id,
                    data.get("bot_id"),
                    name,
                    slug,
                    str(data.get("description", "")),
                    str(scrub_v1_payload(str(data["content_md"]))),
                    str(data.get("source", "custom")),
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM skills WHERE id = ?", (skl_id,)).fetchone()
            assert row is not None
            return self._row_to_skill(row)

    def delete_skill(self, skill_id: str) -> bool:
        with self.write_tx() as conn:
            cur = conn.execute("DELETE FROM skills WHERE id = ?", (skill_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Settings & Connected Apps
    # ------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_json, updated_at FROM settings WHERE id = 'default'"
            ).fetchone()
            defaults: dict[str, Any] = {
                "theme": "light",
                "accent_mode": "bot_color",
                "default_model_id": "gemini-4-carbon-low",
                "default_model": "gemini-4-carbon-low",
                "default_engine_id": "agy",
                "default_engine": "agy",
                "default_thinking_level": "medium",
                "default_project_name": "Grokbotclon",
                "allow_hydrogen": False,
                "include_browser_context": True,
                "notifications_enabled": True,
                "sound_enabled": False,
                "auto_open_computer": True,
                "timezone": "UTC",
                "display_name": "Operator",
            }
            if row is None:
                defaults["updated_at"] = utc_iso_now()
                return defaults
            data = _loads_json(str(row["payload_json"]), {})
            if not isinstance(data, dict):
                data = {}
            merged = {**defaults, **data}
            merged["default_model"] = merged.get("default_model_id", "gemini-4-carbon-low")
            merged["default_engine"] = merged.get("default_engine_id", "agy")
            merged["updated_at"] = str(row["updated_at"])
            return merged

    def update_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        with self.write_tx() as conn:
            current = self.get_settings()
            normalized = dict(updates)
            if "default_model" in normalized and normalized["default_model"] is not None:
                normalized["default_model_id"] = normalized["default_model"]
            if "default_model_id" in normalized and normalized["default_model_id"] is not None:
                normalized["default_model"] = normalized["default_model_id"]
            if "default_engine" in normalized and normalized["default_engine"] is not None:
                normalized["default_engine_id"] = normalized["default_engine"]
            if "default_engine_id" in normalized and normalized["default_engine_id"] is not None:
                normalized["default_engine"] = normalized["default_engine_id"]
            for key, value in normalized.items():
                if value is not None or key == "default_project_name":
                    current[key] = value
            now = utc_iso_now()
            current["updated_at"] = now
            conn.execute(
                """
                INSERT OR REPLACE INTO settings (id, payload_json, updated_at)
                VALUES ('default', ?, ?)
                """,
                (json.dumps(current), now),
            )
            self.append_audit_event(
                actor="operator",
                action="settings.update",
                entity_type="settings",
                entity_id="default",
                decision="allow",
                detail={"keys": sorted(updates.keys())},
                conn=conn,
            )
            return current

    def list_connected_apps(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM connected_apps ORDER BY name ASC"
            ).fetchall()
            return [self._row_to_connected_app(r) for r in rows]

    def update_connected_app(
        self,
        app_id: str,
        updates: dict[str, Any] | None = None,
        *,
        enabled: bool | None = None,
        status: str | None = None,
        account_label: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        merged_updates: dict[str, Any] = dict(updates or {})
        if enabled is not None:
            merged_updates["enabled"] = enabled
        if status is not None:
            merged_updates["status"] = status
        if account_label is not None:
            merged_updates["account_label"] = account_label
        if config is not None:
            merged_updates["config"] = config

        with self.write_tx() as conn:
            row = conn.execute(
                "SELECT * FROM connected_apps WHERE id = ?", (app_id,)
            ).fetchone()
            if row is None:
                raise StoreNotFoundError(f"Connected app not found: {app_id}")
            cols: list[str] = []
            vals: list[Any] = []
            if "enabled" in merged_updates and merged_updates["enabled"] is not None:
                en_val = bool(merged_updates["enabled"])
                cols.append("enabled = ?")
                vals.append(int(en_val))
                if "status" not in merged_updates or merged_updates["status"] is None:
                    cols.append("status = ?")
                    vals.append("connected" if en_val else "disabled")
            if "status" in merged_updates and merged_updates["status"] is not None:
                cols.append("status = ?")
                vals.append(str(merged_updates["status"]))

            existing_cfg = _loads_json(str(row["config_json"]), {})
            if not isinstance(existing_cfg, dict):
                existing_cfg = {}
            new_cfg = dict(existing_cfg)
            cfg_changed = False

            if "config" in merged_updates and merged_updates["config"] is not None:
                raw_cfg = merged_updates["config"]
                if not isinstance(raw_cfg, Mapping):
                    raise StoreValidationError("Connected app config must be a mapping.")
                scrubbed_cfg = scrub_v1_payload(dict(raw_cfg))
                new_cfg = dict(scrubbed_cfg) if isinstance(scrubbed_cfg, Mapping) else {}
                if (
                    "account_label" not in new_cfg
                    and "account_label" in existing_cfg
                    and (
                        "account_label" not in merged_updates
                        or merged_updates["account_label"] is None
                    )
                ):
                    new_cfg["account_label"] = existing_cfg["account_label"]
                cfg_changed = True

            if "account_label" in merged_updates and merged_updates["account_label"] is not None:
                safe_label = str(scrub_v1_payload(str(merged_updates["account_label"]))).strip()
                new_cfg["account_label"] = safe_label
                cfg_changed = True

            if cfg_changed:
                cols.append("config_json = ?")
                vals.append(json.dumps(new_cfg))

            if cols:
                cols.append("updated_at = ?")
                vals.append(utc_iso_now())
                vals.append(app_id)
                conn.execute(
                    f"UPDATE connected_apps SET {', '.join(cols)} WHERE id = ?", vals
                )
            updated_row = conn.execute(
                "SELECT * FROM connected_apps WHERE id = ?", (app_id,)
            ).fetchone()
            assert updated_row is not None
            updated = self._row_to_connected_app(updated_row)
            self.append_audit_event(
                actor="operator",
                action="connected_app.update",
                entity_type="connected_app",
                entity_id=app_id,
                decision="allow",
                detail={
                    "enabled": updated["enabled"],
                    "status": updated["status"],
                    "account_label": updated["account_label"],
                },
                conn=conn,
            )
            return updated

    # ------------------------------------------------------------------
    # Search & Usage
    # ------------------------------------------------------------------

    def search(self, query: str) -> dict[str, list[dict[str, Any]]]:
        cleaned = query.strip()
        if not cleaned:
            return {
                "bots": [],
                "channels": [],
                "messages": [],
                "pages": [],
                "routines": [],
                "skills": [],
            }
        like = f"%{_escape_like(cleaned)}%"
        with self._lock:
            bots = [
                self._row_to_bot(r)
                for r in self._conn.execute(
                    """
                    SELECT * FROM bots
                    WHERE name LIKE ? ESCAPE '\\'
                       OR role_prompt LIKE ? ESCAPE '\\'
                       OR about LIKE ? ESCAPE '\\'
                    ORDER BY pinned DESC, name ASC LIMIT 25
                    """,
                    (like, like, like),
                ).fetchall()
            ]
            channels = [
                self._row_to_channel(r)
                for r in self._conn.execute(
                    "SELECT * FROM channels WHERE name LIKE ? ESCAPE '\\' "
                    "ORDER BY name ASC LIMIT 25",
                    (like,),
                ).fetchall()
            ]
            messages = [
                self._row_to_message(r)
                for r in self._conn.execute(
                    """
                    SELECT * FROM messages
                    WHERE content LIKE ? ESCAPE '\\' OR sender_name LIKE ? ESCAPE '\\'
                    ORDER BY seq DESC LIMIT 25
                    """,
                    (like, like),
                ).fetchall()
            ]
            pages = [
                self._row_to_artifact(r)
                for r in self._conn.execute(
                    """
                    SELECT * FROM artifacts
                    WHERE type = 'page'
                      AND superseded_by_id IS NULL
                      AND (title LIKE ? ESCAPE '\\' OR content_md LIKE ? ESCAPE '\\')
                    ORDER BY updated_at DESC LIMIT 25
                    """,
                    (like, like),
                ).fetchall()
            ]
            routines = [
                self._row_to_routine(r)
                for r in self._conn.execute(
                    """
                    SELECT * FROM routines
                    WHERE name LIKE ? ESCAPE '\\' OR instruction LIKE ? ESCAPE '\\'
                    ORDER BY updated_at DESC LIMIT 25
                    """,
                    (like, like),
                ).fetchall()
            ]
            skills = [
                self._row_to_skill(r)
                for r in self._conn.execute(
                    """
                    SELECT * FROM skills
                    WHERE name LIKE ? ESCAPE '\\'
                       OR description LIKE ? ESCAPE '\\'
                       OR content_md LIKE ? ESCAPE '\\'
                    ORDER BY updated_at DESC LIMIT 25
                    """,
                    (like, like, like),
                ).fetchall()
            ]
        return {
            "bots": bots,
            "channels": channels,
            "messages": messages,
            "pages": pages,
            "routines": routines,
            "skills": skills,
        }

    def get_usage(self, *, active_turns: int = 0) -> dict[str, int]:
        with self._lock:
            return {
                "bots_count": int(self._conn.execute("SELECT COUNT(*) FROM bots").fetchone()[0]),
                "channels_count": int(
                    self._conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0]
                ),
                "messages_count": int(
                    self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
                ),
                "pages_count": int(
                    self._conn.execute(
                        "SELECT COUNT(*) FROM artifacts WHERE type = 'page'"
                    ).fetchone()[0]
                ),
                "routines_count": int(
                    self._conn.execute("SELECT COUNT(*) FROM routines").fetchone()[0]
                ),
                "routine_runs_count": int(
                    self._conn.execute("SELECT COUNT(*) FROM routine_runs").fetchone()[0]
                ),
                "approvals_count": int(
                    self._conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
                ),
                "active_turns": active_turns,
            }
