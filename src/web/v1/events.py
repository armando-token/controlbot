"""Durable & in-memory event bus with epoch-scoped monotonic IDs and SSE streaming (CB-05)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import secrets
import sqlite3
import threading
from collections import deque
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.storage.redaction import redact_payload_strict

_EVT_EPOCH_RE = re.compile(r"^evt_(\d+)_([A-Za-z0-9_-]+)$")
_COLON_EPOCH_RE = re.compile(r"^([A-Za-z0-9_-]+):(\d+)$")
_EVT_LEGACY_RE = re.compile(r"^evt_(\d+)$")
_DIGITS_RE = re.compile(r"^(\d+)$")

_INLINE_TOKEN_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pou]_[A-Za-z0-9_]{8,})\b")
_FORM_FIELD_KEYS: frozenset[str] = frozenset(
    {"name", "label", "secret", "placeholder", "required", "type"}
)
_MAX_DB_SSE_EVENTS = 10000


def utc_iso_now() -> str:
    """Return current UTC timestamp formatted as ISO-8601 Z string."""
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scrub_inline_tokens(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _scrub_inline_tokens(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_inline_tokens(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_inline_tokens(item) for item in value)
    if isinstance(value, str):
        return _INLINE_TOKEN_RE.sub("[REDACTED]", value)
    return value


def _is_secure_form_field_descriptor(obj: dict[Any, Any]) -> bool:
    if "name" not in obj or "label" not in obj or "secret" not in obj:
        return False
    if not isinstance(obj.get("secret"), bool):
        return False
    return all(isinstance(k, str) and k in _FORM_FIELD_KEYS for k in obj)


def _restore_form_field_booleans(original: Any, scrubbed: Any) -> Any:
    if isinstance(original, dict) and isinstance(scrubbed, dict):
        if _is_secure_form_field_descriptor(original):
            restored = dict(scrubbed)
            restored["secret"] = bool(original["secret"])
            return restored
        out: dict[Any, Any] = {}
        for k, v in scrubbed.items():
            if k in original:
                out[k] = _restore_form_field_booleans(original[k], v)
            else:
                out[k] = v
        return out
    if isinstance(original, list) and isinstance(scrubbed, list) and len(original) == len(scrubbed):
        return [
            _restore_form_field_booleans(orig_item, scrub_item)
            for orig_item, scrub_item in zip(original, scrubbed, strict=True)
        ]
    return scrubbed


def scrub_v1_payload(value: Any) -> Any:
    """Scrub a v1 JSON payload through redact_payload_strict while preserving schema flags."""
    redacted = redact_payload_strict(value)
    cleaned = _scrub_inline_tokens(redacted)
    return _restore_form_field_booleans(value, cleaned)


def parse_event_cursor(event_id: str | None) -> tuple[str | None, int | None]:
    """Parse (epoch, seq) from 'evt_<seq>_<epoch>', '<epoch>:<seq>', 'evt_<seq>', or '<seq>'."""
    if not event_id:
        return None, None
    cleaned = event_id.strip()
    if not cleaned:
        return None, None
    if m := _EVT_EPOCH_RE.fullmatch(cleaned):
        return m.group(2), int(m.group(1))
    if m := _COLON_EPOCH_RE.fullmatch(cleaned):
        return m.group(1), int(m.group(2))
    if m := _EVT_LEGACY_RE.fullmatch(cleaned):
        return None, int(m.group(1))
    if m := _DIGITS_RE.fullmatch(cleaned):
        return None, int(m.group(1))
    return None, None


def parse_event_seq(event_id: str | None) -> int | None:
    """Parse monotonic integer sequence from any supported event ID format."""
    return parse_event_cursor(event_id)[1]


class _Subscriber:
    __slots__ = ("loop", "overflowed", "queue")

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        queue: asyncio.Queue[tuple[int, dict[str, Any]]],
    ) -> None:
        self.loop = loop
        self.queue = queue
        self.overflowed = False


class EventBus:
    """Thread-safe event bus with optional SQLite WAL persistence, epoch tracking, and SSE."""

    def __init__(
        self,
        *,
        max_buffer: int = 500,
        subscriber_queue_size: int = 256,
        db_path: Path | str | None = None,
        store: Any | None = None,
        epoch: str | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._max_buffer = max(1, int(max_buffer))
        self._seq = 0
        self._explicit_epoch = epoch.strip() if epoch and epoch.strip() else None
        self._epoch = self._explicit_epoch or secrets.token_hex(4)
        self._buffer: deque[tuple[int, dict[str, Any]]] = deque(maxlen=self._max_buffer)
        self._subscribers: set[_Subscriber] = set()
        self._subscriber_queue_size = max(1, int(subscriber_queue_size))
        self._store: Any | None = None
        self._own_conn: sqlite3.Connection | None = None

        if store is not None:
            self.attach_store(store)
        elif db_path is not None:
            self.attach_db(db_path)

    @property
    def epoch(self) -> str:
        with self._lock:
            return self._epoch

    @property
    def last_event_id(self) -> str | None:
        with self._lock:
            if not self._buffer:
                return None
            return str(self._buffer[-1][1]["id"])

    def close(self) -> None:
        with self._lock:
            if self._own_conn is not None:
                self._own_conn.close()
                self._own_conn = None

    @staticmethod
    def _ensure_sse_tables(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sse_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                epoch TEXT NOT NULL,
                event_type TEXT NOT NULL,
                bot_id TEXT,
                thread_id TEXT,
                turn_id TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sse_events_epoch_seq
                ON sse_events(epoch, seq)
            """
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> tuple[int, dict[str, Any]]:
        seq = int(row["seq"])
        epoch = str(row["epoch"])
        try:
            payload = json.loads(str(row["payload_json"]))
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        event = {
            "id": f"evt_{seq:06d}_{epoch}",
            "ts": str(row["created_at"]),
            "bot_id": row["bot_id"],
            "thread_id": row["thread_id"],
            "turn_id": row["turn_id"],
            "type": str(row["event_type"]),
            "payload": payload,
        }
        return seq, event

    def _hydrate_from_conn(self, conn: sqlite3.Connection) -> None:
        self._ensure_sse_tables(conn)
        if self._explicit_epoch is not None:
            resolved_epoch = self._explicit_epoch
            conn.execute(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('sse_epoch', ?)",
                (resolved_epoch,),
            )
        else:
            row = conn.execute(
                "SELECT value FROM kv_meta WHERE key = 'sse_epoch'"
            ).fetchone()
            if row is not None and str(row["value"]).strip():
                resolved_epoch = str(row["value"]).strip()
            else:
                resolved_epoch = secrets.token_hex(4)
                conn.execute(
                    "INSERT OR REPLACE INTO kv_meta (key, value) VALUES ('sse_epoch', ?)",
                    (resolved_epoch,),
                )
        self._epoch = resolved_epoch

        max_row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM sse_events").fetchone()
        self._seq = int(max_row["max_seq"]) if max_row is not None else 0

        recent_rows = conn.execute(
            """
            SELECT * FROM sse_events
            WHERE epoch = ?
            ORDER BY seq DESC
            LIMIT ?
            """,
            (self._epoch, self._max_buffer),
        ).fetchall()
        self._buffer.clear()
        for row in reversed(recent_rows):
            self._buffer.append(self._row_to_event(row))

    def attach_store(self, store: Any) -> None:
        """Attach an existing WorkspaceStore so SSE events persist in its WAL database."""
        with store._lock, self._lock:
            if self._own_conn is not None:
                self._own_conn.close()
                self._own_conn = None
            self._store = store
            with store.write_tx() as conn:
                self._hydrate_from_conn(conn)

    def attach_db(self, db_path: Path | str) -> None:
        """Attach a SQLite database path directly for standalone durable SSE persistence."""
        path_str = str(db_path)
        if path_str != ":memory:":
            Path(path_str).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self._own_conn is not None:
                self._own_conn.close()
                self._own_conn = None
            self._store = None
            conn = sqlite3.connect(
                path_str,
                timeout=5.0,
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA busy_timeout=5000;")
            self._own_conn = conn
            conn.execute("BEGIN IMMEDIATE;")
            try:
                self._hydrate_from_conn(conn)
                conn.execute("COMMIT;")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                raise

    def recent_events(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._buffer)[-limit:] if limit > 0 else []
            return [dict(ev) for _, ev in items]

    @staticmethod
    def _enqueue_nowait(
        sub: _Subscriber,
        item: tuple[int, dict[str, Any]],
    ) -> None:
        if sub.queue.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                sub.queue.get_nowait()
                sub.overflowed = True
        with contextlib.suppress(asyncio.QueueFull):
            sub.queue.put_nowait(item)

    def _persist_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        bot_id: str | None,
        thread_id: str | None,
        turn_id: str | None,
        created_at: str,
    ) -> int:
        encoded = json.dumps(payload, ensure_ascii=False)
        if self._store is not None:
            with self._store.write_tx() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO sse_events (
                        epoch, event_type, bot_id, thread_id, turn_id, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self._epoch, event_type, bot_id, thread_id, turn_id, encoded, created_at),
                )
                assert cur.lastrowid is not None
                seq = int(cur.lastrowid)
                if seq % 200 == 0:
                    conn.execute(
                        """
                        DELETE FROM sse_events
                        WHERE seq <= (
                            SELECT seq FROM sse_events
                            ORDER BY seq DESC
                            LIMIT 1 OFFSET ?
                        )
                        """,
                        (_MAX_DB_SSE_EVENTS,),
                    )
                return seq

        if self._own_conn is not None:
            conn = self._own_conn
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    INSERT INTO sse_events (
                        epoch, event_type, bot_id, thread_id, turn_id, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self._epoch, event_type, bot_id, thread_id, turn_id, encoded, created_at),
                )
                assert cur.lastrowid is not None
                seq = int(cur.lastrowid)
                if seq % 200 == 0:
                    conn.execute(
                        """
                        DELETE FROM sse_events
                        WHERE seq <= (
                            SELECT seq FROM sse_events
                            ORDER BY seq DESC
                            LIMIT 1 OFFSET ?
                        )
                        """,
                        (_MAX_DB_SSE_EVENTS,),
                    )
                conn.execute("COMMIT;")
                return seq
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                raise

        self._seq += 1
        return self._seq

    def publish(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        bot_id: str | None = None,
        thread_id: str | None = None,
        turn_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist (when DB-backed) then broadcast a scrubbed event to subscribers."""
        scrubbed_payload = scrub_v1_payload(payload)
        if not isinstance(scrubbed_payload, dict):
            scrubbed_payload = {"value": scrubbed_payload}

        ts = utc_iso_now()
        store_lock = self._store._lock if self._store is not None else contextlib.nullcontext()
        with store_lock, self._lock:
            seq = self._persist_event(
                event_type,
                scrubbed_payload,
                bot_id=bot_id,
                thread_id=thread_id,
                turn_id=turn_id,
                created_at=ts,
            )
            self._seq = max(self._seq, seq)
            event: dict[str, Any] = {
                "id": f"evt_{seq:06d}_{self._epoch}",
                "ts": ts,
                "bot_id": bot_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "type": event_type,
                "payload": scrubbed_payload,
            }
            item = (seq, event)
            self._buffer.append(item)
            subscribers = list(self._subscribers)

        running_loop: asyncio.AbstractEventLoop | None = None
        with contextlib.suppress(RuntimeError):
            running_loop = asyncio.get_running_loop()

        for sub in subscribers:
            if sub.loop.is_closed():
                continue
            if running_loop is sub.loop:
                self._enqueue_nowait(sub, item)
            else:
                with contextlib.suppress(RuntimeError):
                    sub.loop.call_soon_threadsafe(self._enqueue_nowait, sub, item)

        return event

    def _build_resync_event(
        self,
        *,
        reason: str,
        client_last_event_id: str | None,
        latest_seq: int,
    ) -> dict[str, Any]:
        return {
            "id": self.last_event_id or f"evt_{latest_seq:06d}_{self._epoch}",
            "ts": utc_iso_now(),
            "bot_id": None,
            "thread_id": None,
            "turn_id": None,
            "type": "stream.resync",
            "payload": {
                "reason": reason,
                "epoch": self._epoch,
                "latest_seq": latest_seq,
                "client_last_event_id": client_last_event_id,
                "last_event_id": self.last_event_id,
            },
        }

    def _prepare_replay(
        self,
        last_event_id: str | None,
    ) -> tuple[dict[str, Any] | None, list[tuple[int, dict[str, Any]]], int]:
        """Compute optional stream.resync event, replay items, and initial last_sent_seq."""
        has_cursor = bool(last_event_id and last_event_id.strip())
        cursor_epoch, after_seq = parse_event_cursor(last_event_id)

        db_conn: sqlite3.Connection | None = None
        if self._store is not None:
            db_conn = self._store._conn
        elif self._own_conn is not None:
            db_conn = self._own_conn

        if db_conn is not None:
            bounds = db_conn.execute(
                "SELECT MIN(seq) AS min_seq, MAX(seq) AS max_seq FROM sse_events WHERE epoch = ?",
                (self._epoch,),
            ).fetchone()
            oldest_seq = (
                int(bounds["min_seq"]) if bounds and bounds["min_seq"] is not None else None
            )
            latest_seq = (
                int(bounds["max_seq"]) if bounds and bounds["max_seq"] is not None else 0
            )

            def _fetch_after(min_exclusive_seq: int) -> list[tuple[int, dict[str, Any]]]:
                rows = db_conn.execute(
                    """
                    SELECT * FROM sse_events
                    WHERE epoch = ? AND seq > ?
                    ORDER BY seq ASC
                    """,
                    (self._epoch, min_exclusive_seq),
                ).fetchall()
                return [self._row_to_event(r) for r in rows]

        else:
            buf = list(self._buffer)
            oldest_seq = buf[0][0] if buf else None
            latest_seq = self._seq

            def _fetch_after(min_exclusive_seq: int) -> list[tuple[int, dict[str, Any]]]:
                return [(s, ev) for s, ev in buf if s > min_exclusive_seq]

        if not has_cursor:
            return None, [], latest_seq

        if after_seq is None:
            resync = self._build_resync_event(
                reason="invalid_cursor",
                client_last_event_id=last_event_id,
                latest_seq=latest_seq,
            )
            return resync, _fetch_after(0), 0

        if cursor_epoch is not None and cursor_epoch != self._epoch:
            resync = self._build_resync_event(
                reason="epoch_mismatch",
                client_last_event_id=last_event_id,
                latest_seq=latest_seq,
            )
            return resync, _fetch_after(0), 0

        if after_seq > latest_seq:
            resync = self._build_resync_event(
                reason="sequence_ahead",
                client_last_event_id=last_event_id,
                latest_seq=latest_seq,
            )
            return resync, _fetch_after(0), 0

        if oldest_seq is not None and after_seq < oldest_seq - 1:
            resync = self._build_resync_event(
                reason="sequence_evicted",
                client_last_event_id=last_event_id,
                latest_seq=latest_seq,
            )
            return resync, _fetch_after(oldest_seq - 1), oldest_seq - 1

        return None, _fetch_after(after_seq), after_seq

    async def subscribe(
        self,
        last_event_id: str | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Replay missed events after last_event_id (or emit resync), then yield live events."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[int, dict[str, Any]]] = asyncio.Queue(
            maxsize=self._subscriber_queue_size
        )
        subscriber = _Subscriber(loop=loop, queue=queue)

        store_lock = self._store._lock if self._store is not None else contextlib.nullcontext()
        with store_lock, self._lock:
            self._subscribers.add(subscriber)
            resync_ev, replay_items, last_sent_seq = self._prepare_replay(last_event_id)

        try:
            if resync_ev is not None:
                yield resync_ev

            for seq, ev in replay_items:
                if seq > last_sent_seq:
                    last_sent_seq = seq
                    yield ev

            while True:
                if subscriber.overflowed:
                    subscriber.overflowed = False
                    yield self._build_resync_event(
                        reason="slow_consumer_overflow",
                        client_last_event_id=last_event_id,
                        latest_seq=max(last_sent_seq, self._seq),
                    )
                seq, ev = await queue.get()
                if subscriber.overflowed:
                    subscriber.overflowed = False
                    yield self._build_resync_event(
                        reason="slow_consumer_overflow",
                        client_last_event_id=last_event_id,
                        latest_seq=max(last_sent_seq, self._seq),
                    )
                if seq <= last_sent_seq:
                    continue
                last_sent_seq = seq
                yield ev
        finally:
            with self._lock:
                self._subscribers.discard(subscriber)

    async def stream_sse(
        self,
        last_event_id: str | None = None,
        *,
        keepalive_seconds: float = 15.0,
    ) -> AsyncGenerator[str, None]:
        """Yield SSE preamble, missed events / resync, and live frames with keepalives."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[int, dict[str, Any]]] = asyncio.Queue(
            maxsize=self._subscriber_queue_size
        )
        subscriber = _Subscriber(loop=loop, queue=queue)

        store_lock = self._store._lock if self._store is not None else contextlib.nullcontext()
        with store_lock, self._lock:
            self._subscribers.add(subscriber)
            resync_ev, replay_items, last_sent_seq = self._prepare_replay(last_event_id)

        try:
            yield ": connected\n\n"
            yield "retry: 2000\n\n"

            if resync_ev is not None:
                yield self.format_sse(resync_ev)

            for seq, ev in replay_items:
                if seq > last_sent_seq:
                    last_sent_seq = seq
                    yield self.format_sse(ev)

            while True:
                if subscriber.overflowed:
                    subscriber.overflowed = False
                    yield self.format_sse(
                        self._build_resync_event(
                            reason="slow_consumer_overflow",
                            client_last_event_id=last_event_id,
                            latest_seq=max(last_sent_seq, self._seq),
                        )
                    )
                try:
                    seq, ev = await asyncio.wait_for(queue.get(), timeout=keepalive_seconds)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if subscriber.overflowed:
                    subscriber.overflowed = False
                    yield self.format_sse(
                        self._build_resync_event(
                            reason="slow_consumer_overflow",
                            client_last_event_id=last_event_id,
                            latest_seq=max(last_sent_seq, self._seq),
                        )
                    )
                if seq <= last_sent_seq:
                    continue
                last_sent_seq = seq
                yield self.format_sse(ev)
        finally:
            with self._lock:
                self._subscribers.discard(subscriber)

    @staticmethod
    def format_sse(event: dict[str, Any]) -> str:
        """Format a single event envelope as an SSE frame."""
        encoded = json.dumps(event, ensure_ascii=False)
        return f"id: {event['id']}\ndata: {encoded}\n\n"
