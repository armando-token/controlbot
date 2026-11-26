"""Cryptographic SHA-256 hash-chaining and verification for workspace audit logs (CB-06)."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from src.storage.redaction import contains_unredacted_secret_strict, redact_payload_strict

GENESIS_PREV_HASH: str = "0" * 64

WORKSPACE_AUDIT_LOG_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS workspace_audit_log (
        seq INTEGER PRIMARY KEY,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        decision TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """.strip(),
    """
    CREATE INDEX IF NOT EXISTS idx_workspace_audit_action
        ON workspace_audit_log(action, seq)
    """.strip(),
    """
    CREATE INDEX IF NOT EXISTS idx_workspace_audit_entity
        ON workspace_audit_log(entity_type, entity_id, seq)
    """.strip(),
    """
    CREATE TRIGGER IF NOT EXISTS trg_workspace_audit_log_no_update
    BEFORE UPDATE ON workspace_audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END
    """.strip(),
    """
    CREATE TRIGGER IF NOT EXISTS trg_workspace_audit_log_no_delete
    BEFORE DELETE ON workspace_audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END
    """.strip(),
)


def ensure_workspace_audit_schema(conn: sqlite3.Connection) -> None:
    """Create the append-only workspace_audit_log table, indexes, and triggers if missing."""
    for stmt in WORKSPACE_AUDIT_LOG_DDL:
        conn.execute(stmt)


def canonical_json(payload: Mapping[str, Any]) -> str:
    """Serialize a mapping deterministically with sorted keys and compact separators."""
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), default=str)


def build_audit_payload(
    *,
    seq: int,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
    decision: str,
    detail: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    """Build the canonical payload structure covered by the SHA-256 chain hash."""
    return {
        "seq": int(seq),
        "actor": str(actor),
        "action": str(action),
        "entity_type": str(entity_type),
        "entity_id": None if entity_id is None else str(entity_id),
        "decision": str(decision),
        "detail": dict(detail),
        "created_at": str(created_at),
    }


def compute_entry_hash(prev_hash: str, payload_dict: Mapping[str, Any]) -> str:
    """Compute SHA-256 entry_hash over '<prev_hash>:<canonical_json(payload_dict)>'."""
    blob = f"{prev_hash}:{canonical_json(payload_dict)}".encode()
    return hashlib.sha256(blob).hexdigest()


def _scrub_audit_detail(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    raw_detail = dict(detail or {})
    scrubbed = redact_payload_strict(raw_detail)
    if not isinstance(scrubbed, Mapping):
        scrubbed = {"value": scrubbed}
    scrubbed_dict = dict(scrubbed)
    if contains_unredacted_secret_strict(scrubbed_dict):
        raise ValueError("Audit log detail contains unredacted secret material.")
    return scrubbed_dict


def append_chained_audit_row(
    conn: sqlite3.Connection,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    decision: str = "allow",
    detail: Mapping[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Scrub detail, link to previous entry_hash inside caller tx, and insert next audit row."""
    scrubbed_detail = _scrub_audit_detail(detail)
    last = conn.execute(
        "SELECT seq, entry_hash FROM workspace_audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if last is not None:
        last_seq = int(last["seq"] if isinstance(last, sqlite3.Row) else last[0])
        last_hash = str(last["entry_hash"] if isinstance(last, sqlite3.Row) else last[1])
        next_seq = last_seq + 1
        prev_hash = last_hash
    else:
        next_seq = 1
        prev_hash = GENESIS_PREV_HASH

    ts = created_at or datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = build_audit_payload(
        seq=next_seq,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        decision=decision,
        detail=scrubbed_detail,
        created_at=ts,
    )
    entry_hash = compute_entry_hash(prev_hash, payload)
    detail_json = canonical_json(scrubbed_detail)

    conn.execute(
        """
        INSERT INTO workspace_audit_log (
            seq, prev_hash, entry_hash, actor, action, entity_type,
            entity_id, decision, detail_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            next_seq,
            prev_hash,
            entry_hash,
            str(actor),
            str(action),
            str(entity_type),
            None if entity_id is None else str(entity_id),
            str(decision),
            detail_json,
            ts,
        ),
    )
    return {
        "seq": next_seq,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "actor": str(actor),
        "action": str(action),
        "entity_type": str(entity_type),
        "entity_id": None if entity_id is None else str(entity_id),
        "decision": str(decision),
        "detail": scrubbed_dict_copy(scrubbed_detail),
        "created_at": ts,
    }


def scrubbed_dict_copy(detail: Mapping[str, Any]) -> dict[str, Any]:
    return dict(detail)


def _row_field(row: Mapping[str, Any] | sqlite3.Row, key: str) -> Any:
    return row[key]


def _has_key(row: Mapping[str, Any] | sqlite3.Row, key: str) -> bool:
    if isinstance(row, sqlite3.Row):
        return key in set(row.keys())
    return key in row


def verify_chain(
    rows: Sequence[Mapping[str, Any] | sqlite3.Row],
    *,
    expected_count: int | None = None,
    expected_head_hash: str | None = None,
) -> dict[str, Any]:
    """Verify cryptographic continuity, contiguous sequence, and payload integrity."""
    if not rows:
        if expected_count is not None and expected_count > 0:
            return {
                "valid": False,
                "checked": 0,
                "broken_seq": 1,
                "reason": "tail_truncation",
                "head_hash": GENESIS_PREV_HASH,
            }
        if (
            expected_head_hash is not None
            and not hmac.compare_digest(GENESIS_PREV_HASH, expected_head_hash)
        ):
            return {
                "valid": False,
                "checked": 0,
                "broken_seq": 1,
                "reason": "head_hash_mismatch",
                "head_hash": GENESIS_PREV_HASH,
            }
        return {
            "valid": True,
            "checked": 0,
            "broken_seq": None,
            "reason": None,
            "head_hash": GENESIS_PREV_HASH,
        }

    expected_prev = GENESIS_PREV_HASH
    checked = 0
    for idx, row in enumerate(rows, start=1):
        try:
            row_seq = int(_row_field(row, "seq"))
        except (TypeError, ValueError, KeyError, IndexError):
            return {
                "valid": False,
                "checked": checked,
                "broken_seq": idx,
                "reason": "invalid_sequence",
                "head_hash": expected_prev,
            }

        if row_seq != idx:
            return {
                "valid": False,
                "checked": checked,
                "broken_seq": idx,
                "reason": "sequence_gap",
                "head_hash": expected_prev,
            }

        row_prev = str(_row_field(row, "prev_hash"))
        row_hash = str(_row_field(row, "entry_hash"))
        if not hmac.compare_digest(row_prev, expected_prev):
            return {
                "valid": False,
                "checked": checked,
                "broken_seq": row_seq,
                "reason": "prev_hash_mismatch",
                "head_hash": expected_prev,
            }

        if _has_key(row, "detail") and isinstance(_row_field(row, "detail"), Mapping):
            detail_obj: dict[str, Any] = dict(_row_field(row, "detail"))
        else:
            raw_json = _row_field(row, "detail_json")
            try:
                parsed = json.loads(str(raw_json))
            except (json.JSONDecodeError, TypeError):
                return {
                    "valid": False,
                    "checked": checked,
                    "broken_seq": row_seq,
                    "reason": "corrupt_detail_json",
                    "head_hash": expected_prev,
                }
            if not isinstance(parsed, Mapping):
                return {
                    "valid": False,
                    "checked": checked,
                    "broken_seq": row_seq,
                    "reason": "corrupt_detail_json",
                    "head_hash": expected_prev,
                }
            detail_obj = dict(parsed)

        payload = build_audit_payload(
            seq=row_seq,
            actor=str(_row_field(row, "actor")),
            action=str(_row_field(row, "action")),
            entity_type=str(_row_field(row, "entity_type")),
            entity_id=(
                None
                if _row_field(row, "entity_id") is None
                else str(_row_field(row, "entity_id"))
            ),
            decision=str(_row_field(row, "decision")),
            detail=detail_obj,
            created_at=str(_row_field(row, "created_at")),
        )
        expected_hash = compute_entry_hash(row_prev, payload)
        if not hmac.compare_digest(row_hash, expected_hash):
            return {
                "valid": False,
                "checked": checked,
                "broken_seq": row_seq,
                "reason": "entry_hash_mismatch",
                "head_hash": expected_prev,
            }

        expected_prev = row_hash
        checked += 1

    if expected_count is not None and checked < expected_count:
        return {
            "valid": False,
            "checked": checked,
            "broken_seq": checked + 1,
            "reason": "tail_truncation",
            "head_hash": expected_prev,
        }
    if (
        expected_head_hash is not None
        and not hmac.compare_digest(expected_prev, expected_head_hash)
    ):
        return {
            "valid": False,
            "checked": checked,
            "broken_seq": checked,
            "reason": "head_hash_mismatch",
            "head_hash": expected_prev,
        }

    return {
        "valid": True,
        "checked": checked,
        "broken_seq": None,
        "reason": None,
        "head_hash": expected_prev,
    }
