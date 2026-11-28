"""Telemetry ingestion, strict redaction, correlation, and deduplicated QA queue."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import httpx

from src.contracts.common import ensure_utc, utc_now
from src.factory.db import FactoryStore
from src.qa.isolation import (
    _DB_PATH_ENV_KEY,
    _LOG_FILES,
    LogCursor,
    _sanitize_record,
    assert_safe_mutation_path,
    contains_encoded_auth,
    contains_unredacted_url_secret,
    read_sanitized_logs,
)
from src.qa.models import (
    CampaignState,
    LaneName,
    QAFailureItem,
    QAItemState,
    RunRecord,
    Severity,
)
from src.storage.redaction import contains_unredacted_secret_strict

_SEVERITY_RANK: dict[Severity, int] = {
    "P0": 0,
    "P1": 1,
    "P2": 2,
    "P3": 3,
}

_STATE_PROGRESSION_RANK: dict[QAItemState, int] = {
    "observed": 0,
    "reproduced": 1,
    "in_repair": 2,
    "candidate_verified": 3,
    "accepted_qa": 4,
    "flaky": 5,
    "blocked": 5,
    "parked": 5,
}

_ALLOWED_TRANSITIONS: dict[QAItemState, frozenset[QAItemState]] = {
    "observed": frozenset({"reproduced", "flaky", "blocked", "parked"}),
    "reproduced": frozenset({"in_repair", "flaky", "blocked", "parked"}),
    "flaky": frozenset({"reproduced", "blocked", "parked"}),
    "in_repair": frozenset({"candidate_verified", "reproduced", "flaky", "blocked", "parked"}),
    "candidate_verified": frozenset({"accepted_qa", "reproduced", "blocked"}),
    "accepted_qa": frozenset({"reproduced"}),
    "blocked": frozenset({"observed", "reproduced", "parked"}),
    "parked": frozenset({"reproduced"}),
}

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_PREFIXED_ID_RE = re.compile(
    r"\b(?:req|fail|evt|trn|msg|run|sess|tok)_[0-9a-f_]{4,}\b",
    re.IGNORECASE,
)
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_LOCALHOST_PORT_RE = re.compile(r"\b(?:127\.0\.0\.1|localhost):\d+\b", re.IGNORECASE)
_HEX_ADDR_RE = re.compile(r"\b0x[0-9a-f]+\b", re.IGNORECASE)
_TMP_PATH_RE = re.compile(r"/tmp/[^\s'\"`]+")
_ATTEMPT_NUM_RE = re.compile(r"\battempt\s+\d+\b", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")

_P0_MARKERS: tuple[str, ...] = (
    "live_db_leak",
    "secret_leak",
    "unredacted_secret",
    "isolation_breach",
    "isolation_boundary_violation",
    "data_loss",
    "credential_leak",
    "vault_leak",
)


def normalize_failure_signature(raw_text: str) -> str:
    """Normalize dynamic IDs/timestamps/ports while keeping routes & error tokens."""
    text = raw_text.strip()
    if not text:
        return "unknown_failure"
    text = _UUID_RE.sub("<uuid>", text)
    text = _PREFIXED_ID_RE.sub("<id>", text)
    text = _ISO_TS_RE.sub("<ts>", text)
    text = _LOCALHOST_PORT_RE.sub("<host>", text)
    text = _HEX_ADDR_RE.sub("<hex>", text)
    text = _TMP_PATH_RE.sub("<tmp>", text)
    text = _ATTEMPT_NUM_RE.sub("attempt <n>", text)
    text = _WHITESPACE_RE.sub(" ", text).strip().lower()
    if len(text) > 160:
        text = text[:160].rstrip()
    return text or "unknown_failure"


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    os.replace(tmp_path, path)


def _has_unredacted_secret_any(value: Any) -> bool:
    if contains_unredacted_secret_strict(value):
        return True
    if isinstance(value, Mapping):
        return any(
            _has_unredacted_secret_any(k) or _has_unredacted_secret_any(v)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_has_unredacted_secret_any(item) for item in value)
    if isinstance(value, str):
        return contains_encoded_auth(value) or contains_unredacted_url_secret(value)
    if value is not None:
        raw = str(value)
        return contains_encoded_auth(raw) or contains_unredacted_url_secret(raw)
    return False


def assert_strictly_redacted(payload: Any, *, label: str = "payload") -> Any:
    """Sanitize payload strictly and fail closed if any secret token remains."""
    sanitized = _sanitize_record(payload)
    if _has_unredacted_secret_any(sanitized):
        raise ValueError(f"Refusing to persist unredacted secret in {label}.")
    return sanitized


def resolve_campaign_db_path(
    campaign_dir: Path,
    state: CampaignState | None = None,
) -> Path:
    """Resolve the unified SQLite WAL database path for a campaign."""
    if state is not None and state.factory_db_path:
        return Path(state.factory_db_path).resolve()
    return (campaign_dir / "factory.sqlite3").resolve()


def _validate_runtime_db_env(repo_root: Path | None = None) -> list[Path]:
    forbidden: list[Path] = []
    if repo_root is not None:
        resolved_repo = repo_root.resolve()
        forbidden.append(resolved_repo / "var" / "controlbot.sqlite3")
        forbidden.append(resolved_repo / "var" / "controlbot_workspace.sqlite3")
    env_db = os.environ.get(_DB_PATH_ENV_KEY, "").strip()
    if env_db:
        env_path = Path(env_db).expanduser().resolve()
        assert_safe_mutation_path(env_path, repo_root=repo_root)
        forbidden.append(env_path)
    return forbidden


def open_campaign_store(
    campaign_dir: Path,
    state: CampaignState | None = None,
    *,
    repo_root: Path | None = None,
) -> FactoryStore:
    """Open and initialize the unified FactoryStore + QA tables for a campaign."""
    safe_dir = assert_safe_mutation_path(campaign_dir, repo_root=repo_root)
    safe_dir.mkdir(parents=True, exist_ok=True)
    db_path = resolve_campaign_db_path(safe_dir, state)
    assert_safe_mutation_path(db_path, repo_root=repo_root)
    forbidden = _validate_runtime_db_env(repo_root=repo_root)
    store = FactoryStore(db_path, forbidden_db_paths=forbidden)
    store.init_db()
    if state is not None:
        sync_campaign_record(store, state)
    return store


def sync_campaign_record(store: FactoryStore, state: CampaignState) -> None:
    """Persist CampaignState into qa_campaigns table."""
    now_iso = ensure_utc(utc_now()).isoformat()
    created_iso = ensure_utc(state.created_at).isoformat()
    updated_iso = ensure_utc(state.updated_at).isoformat() if state.updated_at else now_iso
    sanitized_state = assert_strictly_redacted(
        json.loads(state.model_dump_json()), label="qa_campaigns.state_json"
    )
    state_json = json.dumps(sanitized_state, sort_keys=True, ensure_ascii=False)
    with store.write_tx() as conn:
        conn.execute(
            """
            INSERT INTO qa_campaigns (
                campaign_id, base_sha, last_accepted_sha, qa_branch, lane, status,
                state_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(campaign_id) DO UPDATE SET
                base_sha=excluded.base_sha,
                last_accepted_sha=excluded.last_accepted_sha,
                qa_branch=excluded.qa_branch,
                lane=excluded.lane,
                status=excluded.status,
                state_json=excluded.state_json,
                updated_at=excluded.updated_at;
            """,
            (
                state.campaign_id,
                state.base_sha,
                state.last_accepted_sha,
                state.qa_branch,
                state.lane,
                state.status,
                state_json,
                created_iso,
                updated_iso,
            ),
        )


def save_campaign_state(
    campaign_dir: Path,
    state: CampaignState,
    *,
    store: FactoryStore | None = None,
) -> Path:
    """Persist campaign.json atomically and sync qa_campaigns if store provided."""
    campaign_path = campaign_dir / "campaign.json"
    sanitized = assert_strictly_redacted(
        json.loads(state.model_dump_json()), label="campaign.json"
    )
    _atomic_write_text(
        campaign_path,
        json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n",
    )
    if store is not None:
        sync_campaign_record(store, state)
    return campaign_path


def _backlog_status_for_qa_state(state: QAItemState) -> Literal[
    "pending", "in_progress", "completed", "rejected", "paused"
]:
    if state == "reproduced":
        return "pending"
    if state == "in_repair":
        return "in_progress"
    if state == "accepted_qa":
        return "completed"
    return "paused"


def _row_to_qa_item(row: Mapping[str, Any]) -> QAFailureItem:
    payload_raw = row.get("payload_json")
    if isinstance(payload_raw, str) and payload_raw.strip():
        data = json.loads(payload_raw)
        if isinstance(data, dict):
            return QAFailureItem.model_validate(data)
    return QAFailureItem(
        item_id=str(row["item_id"]),
        dedup_key=str(row["dedup_key"]),
        case_id=str(row["case_id"]),
        subsystem=str(row["subsystem"]),
        normalized_signature=str(row["normalized_signature"]),
        severity=row["severity"],
        state=row["state"],
        source=row.get("source") or "e2e",
        summary=str(row["summary"]),
        first_seen_sha=str(row["first_seen_sha"]),
        last_seen_sha=str(row["last_seen_sha"]),
        environment_lane=row["environment_lane"],
        repro_command=str(row.get("repro_command") or ""),
        evidence_paths=json.loads(str(row.get("evidence_paths_json") or "[]")),
        factory_item_id=row.get("factory_item_id"),
        attempts=int(row.get("attempts") or 0),
        run_ids=json.loads(str(row.get("run_ids_json") or "[]")),
        occurrence_count=int(row.get("occurrence_count") or 1),
        first_seen_at=datetime.fromisoformat(str(row["first_seen_at"])),
        last_seen_at=datetime.fromisoformat(str(row["last_seen_at"])),
        blocked_reason=row.get("blocked_reason"),
        next_diagnostic=row.get("next_diagnostic"),
        parent_item_id=row.get("parent_item_id"),
        correlation_ids=json.loads(str(row.get("correlation_ids_json") or "[]")),
        pass_count=int(row.get("pass_count") or 0),
        fail_count=int(row.get("fail_count") or 1),
        flaky_reason=row.get("flaky_reason"),
        repro_test_path=row.get("repro_test_path"),
        candidate_ids=json.loads(str(row.get("candidate_ids_json") or "[]")),
    )


def _upsert_qa_item_in_tx(
    conn: Any,
    *,
    campaign_id: str,
    item: QAFailureItem,
) -> QAFailureItem:
    sanitized_dict = assert_strictly_redacted(
        json.loads(item.model_dump_json()), label="qa_items"
    )
    clean_item = QAFailureItem.model_validate(sanitized_dict)
    factory_item_id = clean_item.factory_item_id or f"fb-{clean_item.item_id}"
    if clean_item.factory_item_id != factory_item_id:
        clean_item = clean_item.model_copy(update={"factory_item_id": factory_item_id})
        sanitized_dict = json.loads(clean_item.model_dump_json())

    now_iso = ensure_utc(utc_now()).isoformat()
    first_iso = ensure_utc(clean_item.first_seen_at).isoformat()
    last_iso = ensure_utc(clean_item.last_seen_at).isoformat()
    fb_status = _backlog_status_for_qa_state(clean_item.state)
    repro_cmd = (
        clean_item.repro_command.strip()
        or f"python -m src.qa reevaluate --item {clean_item.item_id}"
    )

    conn.execute(
        """
        INSERT INTO factory_backlog (
            item_id, title, priority, status, hypothesis, target_metric,
            baseline_repro_cmd, max_attempts, attempts_used, attempt_count,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(item_id) DO UPDATE SET
            title=excluded.title,
            priority=excluded.priority,
            status=excluded.status,
            hypothesis=excluded.hypothesis,
            baseline_repro_cmd=excluded.baseline_repro_cmd,
            attempts_used=MAX(factory_backlog.attempts_used, excluded.attempts_used),
            attempt_count=MAX(factory_backlog.attempt_count, excluded.attempt_count),
            updated_at=excluded.updated_at;
        """,
        (
            factory_item_id,
            clean_item.summary[:200],
            _SEVERITY_RANK[clean_item.severity] + 1,
            fb_status,
            f"Fix {clean_item.case_id}/{clean_item.subsystem}: {clean_item.normalized_signature}",
            "failing_assertions",
            repro_cmd,
            2,
            clean_item.attempts,
            clean_item.attempts,
            first_iso,
            now_iso,
        ),
    )

    payload_json = json.dumps(sanitized_dict, sort_keys=True, ensure_ascii=False)
    conn.execute(
        """
        INSERT INTO qa_items (
            item_id, campaign_id, factory_item_id, parent_item_id, dedup_key,
            case_id, subsystem, normalized_signature, severity, state, source,
            summary, first_seen_sha, last_seen_sha, environment_lane, repro_command,
            repro_test_path, blocked_reason, flaky_reason, next_diagnostic,
            occurrence_count, pass_count, fail_count, attempts,
            run_ids_json, correlation_ids_json, evidence_paths_json, candidate_ids_json,
            payload_json, first_seen_at, last_seen_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(item_id) DO UPDATE SET
            factory_item_id=excluded.factory_item_id,
            parent_item_id=COALESCE(excluded.parent_item_id, qa_items.parent_item_id),
            severity=excluded.severity,
            state=excluded.state,
            source=excluded.source,
            summary=excluded.summary,
            last_seen_sha=excluded.last_seen_sha,
            repro_command=CASE
                WHEN excluded.repro_command != '' THEN excluded.repro_command
                ELSE qa_items.repro_command
            END,
            repro_test_path=COALESCE(excluded.repro_test_path, qa_items.repro_test_path),
            blocked_reason=excluded.blocked_reason,
            flaky_reason=excluded.flaky_reason,
            next_diagnostic=excluded.next_diagnostic,
            occurrence_count=excluded.occurrence_count,
            pass_count=excluded.pass_count,
            fail_count=excluded.fail_count,
            attempts=excluded.attempts,
            run_ids_json=excluded.run_ids_json,
            correlation_ids_json=excluded.correlation_ids_json,
            evidence_paths_json=excluded.evidence_paths_json,
            candidate_ids_json=excluded.candidate_ids_json,
            payload_json=excluded.payload_json,
            last_seen_at=excluded.last_seen_at;
        """,
        (
            clean_item.item_id,
            campaign_id,
            factory_item_id,
            clean_item.parent_item_id,
            clean_item.dedup_key,
            clean_item.case_id,
            clean_item.subsystem,
            clean_item.normalized_signature,
            clean_item.severity,
            clean_item.state,
            clean_item.source,
            clean_item.summary,
            clean_item.first_seen_sha,
            clean_item.last_seen_sha,
            clean_item.environment_lane,
            clean_item.repro_command,
            clean_item.repro_test_path,
            clean_item.blocked_reason,
            clean_item.flaky_reason,
            clean_item.next_diagnostic,
            clean_item.occurrence_count,
            clean_item.pass_count,
            clean_item.fail_count,
            clean_item.attempts,
            json.dumps(clean_item.run_ids),
            json.dumps(clean_item.correlation_ids),
            json.dumps(clean_item.evidence_paths),
            json.dumps(clean_item.candidate_ids),
            payload_json,
            first_iso,
            last_iso,
        ),
    )
    return clean_item


def _merge_ordered_unique(existing: Sequence[str], additions: Sequence[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for val in (*existing, *additions):
        s = str(val).strip()
        if s and s not in seen:
            seen.add(s)
            merged.append(s)
    return merged


def record_failure_observation(
    store: FactoryStore,
    state: CampaignState,
    *,
    case_id: str,
    subsystem: str,
    raw_signature: str,
    severity: Severity,
    summary: str,
    sha: str | None = None,
    lane: LaneName | None = None,
    source: Literal["log", "diagnostics_api", "e2e", "ux", "watchdog"] = "e2e",
    repro_command: str = "",
    repro_test_path: str | None = None,
    run_id: str | None = None,
    correlation_ids: Sequence[str] = (),
    evidence_paths: Sequence[str] = (),
    initial_state: QAItemState = "observed",
    parent_item_id: str | None = None,
    observed_at: datetime | None = None,
) -> QAFailureItem:
    """Insert or deduplicate a QA failure observation into qa_items and factory_backlog."""
    clean_case_id = str(_sanitize_record(case_id))
    clean_subsystem = str(_sanitize_record(subsystem))
    clean_raw_signature = str(_sanitize_record(raw_signature))
    norm_sig = str(_sanitize_record(normalize_failure_signature(clean_raw_signature)))
    dedup_key = str(_sanitize_record(f"{clean_case_id}:{clean_subsystem}:{norm_sig}"))
    clean_summary = (
        str(_sanitize_record(summary.strip())) or f"{clean_case_id} {clean_subsystem} failure"
    )
    env_lane: LaneName = lane or state.lane
    seen_sha = sha or state.last_accepted_sha or state.base_sha
    seen_at = ensure_utc(observed_at or utc_now())
    clean_corr = [str(_sanitize_record(str(c))) for c in correlation_ids if str(c).strip()]
    clean_ev = [str(_sanitize_record(str(e))) for e in evidence_paths if str(e).strip()]
    clean_runs = [run_id] if run_id else []

    with store.write_tx() as conn:
        existing_row = conn.execute(
            """
            SELECT * FROM qa_items
            WHERE campaign_id = ? AND dedup_key = ? AND environment_lane = ?;
            """,
            (state.campaign_id, dedup_key, env_lane),
        ).fetchone()
        if existing_row is not None:
            existing = _row_to_qa_item(dict(existing_row))
            best_sev = (
                severity
                if _SEVERITY_RANK[severity] < _SEVERITY_RANK[existing.severity]
                else existing.severity
            )
            next_state = existing.state
            if existing.state == "observed" and initial_state == "reproduced":
                next_state = "reproduced"
            updated = existing.model_copy(
                update={
                    "severity": best_sev,
                    "state": next_state,
                    "last_seen_sha": seen_sha,
                    "last_seen_at": seen_at,
                    "occurrence_count": existing.occurrence_count + 1,
                    "fail_count": existing.fail_count + 1,
                    "run_ids": _merge_ordered_unique(existing.run_ids, clean_runs),
                    "correlation_ids": _merge_ordered_unique(existing.correlation_ids, clean_corr),
                    "evidence_paths": _merge_ordered_unique(existing.evidence_paths, clean_ev),
                    "repro_command": existing.repro_command or repro_command,
                    "repro_test_path": existing.repro_test_path or repro_test_path,
                    "parent_item_id": existing.parent_item_id or parent_item_id,
                }
            )
            return _upsert_qa_item_in_tx(conn, campaign_id=state.campaign_id, item=updated)

        digest = hashlib.sha256(f"{state.campaign_id}:{dedup_key}:{env_lane}".encode()).hexdigest()[
            :10
        ]
        item_id = f"qa-{digest}"
        new_item = QAFailureItem(
            item_id=item_id,
            dedup_key=dedup_key,
            case_id=clean_case_id,
            subsystem=clean_subsystem,
            normalized_signature=norm_sig,
            severity=severity,
            state=initial_state,
            source=source,
            summary=clean_summary,
            first_seen_sha=seen_sha,
            last_seen_sha=seen_sha,
            environment_lane=env_lane,
            repro_command=repro_command,
            evidence_paths=clean_ev,
            factory_item_id=f"fb-{item_id}",
            attempts=0,
            run_ids=clean_runs,
            occurrence_count=1,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
            parent_item_id=parent_item_id,
            correlation_ids=clean_corr,
            pass_count=0,
            fail_count=1,
            repro_test_path=repro_test_path,
        )
        return _upsert_qa_item_in_tx(conn, campaign_id=state.campaign_id, item=new_item)


def get_qa_item(store: FactoryStore, campaign_id: str, item_id: str) -> QAFailureItem | None:
    """Fetch a single QA item by item_id."""
    with store.read_tx() as conn:
        row = conn.execute(
            "SELECT * FROM qa_items WHERE campaign_id = ? AND item_id = ?;",
            (campaign_id, item_id),
        ).fetchone()
    return _row_to_qa_item(dict(row)) if row is not None else None


def list_qa_items(
    store: FactoryStore,
    campaign_id: str,
    *,
    states: Sequence[QAItemState] | None = None,
) -> list[QAFailureItem]:
    """List QA items sorted by P0..P3 priority, occurrence_count desc, first_seen_at asc."""
    with store.read_tx() as conn:
        if states:
            placeholders = ",".join("?" for _ in states)
            rows = conn.execute(
                f"SELECT * FROM qa_items WHERE campaign_id = ? AND state IN ({placeholders});",
                (campaign_id, *states),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM qa_items WHERE campaign_id = ?;",
                (campaign_id,),
            ).fetchall()
    items = [_row_to_qa_item(dict(r)) for r in rows]
    items.sort(
        key=lambda it: (
            _SEVERITY_RANK[it.severity],
            -it.occurrence_count,
            ensure_utc(it.first_seen_at),
            it.item_id,
        )
    )
    return items


def upsert_qa_item(store: FactoryStore, campaign_id: str, item: QAFailureItem) -> QAFailureItem:
    """Persist or update a QAFailureItem directly (syncing factory_backlog)."""
    with store.write_tx() as conn:
        return _upsert_qa_item_in_tx(conn, campaign_id=campaign_id, item=item)


def transition_qa_item_state(
    store: FactoryStore,
    campaign_id: str,
    item_id: str,
    new_state: QAItemState,
    *,
    blocked_reason: str | None = None,
    flaky_reason: str | None = None,
    next_diagnostic: str | None = None,
    attempts_delta: int = 0,
    candidate_id: str | None = None,
    repro_test_hash: str | None = None,
    locked_criterion_hash: str | None = None,
) -> QAFailureItem:
    """Transition a QA item strictly following the 8-state lifecycle."""
    with store.write_tx() as conn:
        row = conn.execute(
            "SELECT * FROM qa_items WHERE campaign_id = ? AND item_id = ?;",
            (campaign_id, item_id),
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Unknown QA item {item_id!r} in campaign {campaign_id!r}.")
        item = _row_to_qa_item(dict(row))
        if new_state != item.state:
            allowed = _ALLOWED_TRANSITIONS[item.state]
            if new_state not in allowed:
                raise ValueError(
                    f"Illegal QA item state transition for {item_id!r}: "
                    f"{item.state!r} -> {new_state!r} (allowed={sorted(allowed)})."
                )
        cand_ids = (
            _merge_ordered_unique(item.candidate_ids, [candidate_id])
            if candidate_id
            else item.candidate_ids
        )
        updated = item.model_copy(
            update={
                "state": new_state,
                "blocked_reason": (
                    blocked_reason if blocked_reason is not None else item.blocked_reason
                ),
                "flaky_reason": flaky_reason if flaky_reason is not None else item.flaky_reason,
                "next_diagnostic": (
                    next_diagnostic if next_diagnostic is not None else item.next_diagnostic
                ),
                "attempts": max(0, item.attempts + attempts_delta),
                "candidate_ids": cand_ids,
                "repro_test_hash": (
                    repro_test_hash if repro_test_hash is not None else item.repro_test_hash
                ),
                "locked_criterion_hash": (
                    locked_criterion_hash
                    if locked_criterion_hash is not None
                    else item.locked_criterion_hash
                ),
                "last_seen_at": utc_now(),
            }
        )
        return _upsert_qa_item_in_tx(conn, campaign_id=campaign_id, item=updated)


def record_item_probe_outcome(
    store: FactoryStore,
    campaign_id: str,
    item_id: str,
    *,
    passed: bool,
    run_id: str | None = None,
) -> QAFailureItem:
    """Record a baseline repro probe outcome; alternating pass/fail marks item `flaky`."""
    with store.write_tx() as conn:
        row = conn.execute(
            "SELECT * FROM qa_items WHERE campaign_id = ? AND item_id = ?;",
            (campaign_id, item_id),
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Unknown QA item {item_id!r} in campaign {campaign_id!r}.")
        item = _row_to_qa_item(dict(row))
        new_passes = item.pass_count + (1 if passed else 0)
        new_fails = item.fail_count + (0 if passed else 1)
        new_runs = _merge_ordered_unique(item.run_ids, [run_id] if run_id else ())

        next_state = item.state
        flaky_reason = item.flaky_reason
        if new_passes > 0 and new_fails > 0:
            next_state = "flaky"
            flaky_reason = (
                f"Alternating pass/fail observed on same SHA "
                f"(pass_count={new_passes}, fail_count={new_fails})."
            )
        elif not passed and item.state == "observed":
            next_state = "reproduced"

        updated = item.model_copy(
            update={
                "pass_count": new_passes,
                "fail_count": new_fails,
                "run_ids": new_runs,
                "state": next_state,
                "flaky_reason": flaky_reason,
                "last_seen_at": utc_now(),
            }
        )
        return _upsert_qa_item_in_tx(conn, campaign_id=campaign_id, item=updated)


def sync_failures_jsonl_from_store(
    store: FactoryStore,
    campaign_id: str,
    campaign_dir: Path,
) -> Path:
    """Emit deterministic, strictly-redacted failures.jsonl from SQLite qa_items."""
    items = list_qa_items(store, campaign_id)
    lines: list[str] = []
    for item in items:
        sanitized = assert_strictly_redacted(
            json.loads(item.model_dump_json()), label=f"failures.jsonl:{item.item_id}"
        )
        lines.append(json.dumps(sanitized, ensure_ascii=False))
    failures_path = campaign_dir / "failures.jsonl"
    _atomic_write_text(failures_path, ("\n".join(lines) + "\n") if lines else "")
    return failures_path


def import_failures_jsonl_into_store(
    store: FactoryStore,
    state: CampaignState,
    campaign_dir: Path,
) -> list[QAFailureItem]:
    """Load/merge failures.jsonl entries into SQLite qa_items + factory_backlog."""
    failures_path = campaign_dir / "failures.jsonl"
    if not failures_path.is_file():
        return list_qa_items(store, state.campaign_id)
    imported: list[QAFailureItem] = []
    raw_lines = failures_path.read_text(encoding="utf-8").splitlines()
    with store.write_tx() as conn:
        for raw_line in raw_lines:
            line = raw_line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                continue
            sanitized = assert_strictly_redacted(parsed, label="failures.jsonl.import")
            item = QAFailureItem.model_validate(sanitized)
            existing_row = conn.execute(
                "SELECT * FROM qa_items WHERE campaign_id = ? AND item_id = ?;",
                (state.campaign_id, item.item_id),
            ).fetchone()
            if existing_row is not None:
                existing = _row_to_qa_item(dict(existing_row))
                merged_attempts = max(
                    existing.attempts,
                    item.attempts,
                    state.attempts.get(item.item_id, 0),
                )
                preserved_state = (
                    existing.state
                    if (
                        _STATE_PROGRESSION_RANK[existing.state]
                        >= _STATE_PROGRESSION_RANK[item.state]
                    )
                    else item.state
                )
                preserved_severity = (
                    existing.severity
                    if _SEVERITY_RANK[existing.severity] <= _SEVERITY_RANK[item.severity]
                    else item.severity
                )
                existing_higher_or_equal_state = (
                    _STATE_PROGRESSION_RANK[existing.state]
                    >= _STATE_PROGRESSION_RANK[item.state]
                )
                item_is_older = ensure_utc(item.last_seen_at) <= ensure_utc(
                    existing.last_seen_at
                )
                preserved_last_seen_sha = (
                    existing.last_seen_sha
                    if (
                        existing_higher_or_equal_state
                        and item_is_older
                        and existing.last_seen_sha
                    )
                    else (item.last_seen_sha or existing.last_seen_sha)
                )
                preserved_repro_command = (
                    item.repro_command
                    if item.repro_command.strip()
                    else existing.repro_command
                )
                # Preserve higher-progression SQLite state and probe/audit metadata
                merged = item.model_copy(
                    update={
                        "state": preserved_state,
                        "severity": preserved_severity,
                        "last_seen_sha": preserved_last_seen_sha,
                        "repro_command": preserved_repro_command,
                        "attempts": merged_attempts,
                        "occurrence_count": max(existing.occurrence_count, item.occurrence_count),
                        "pass_count": max(existing.pass_count, item.pass_count),
                        "fail_count": max(existing.fail_count, item.fail_count),
                        "flaky_reason": existing.flaky_reason or item.flaky_reason,
                        "blocked_reason": existing.blocked_reason or item.blocked_reason,
                        "next_diagnostic": existing.next_diagnostic or item.next_diagnostic,
                        "repro_test_path": existing.repro_test_path or item.repro_test_path,
                        "repro_test_hash": existing.repro_test_hash or item.repro_test_hash,
                        "locked_criterion_hash": (
                            existing.locked_criterion_hash or item.locked_criterion_hash
                        ),
                        "parent_item_id": existing.parent_item_id or item.parent_item_id,
                        "first_seen_at": min(
                            ensure_utc(existing.first_seen_at), ensure_utc(item.first_seen_at)
                        ),
                        "last_seen_at": max(
                            ensure_utc(existing.last_seen_at), ensure_utc(item.last_seen_at)
                        ),
                        "run_ids": _merge_ordered_unique(existing.run_ids, item.run_ids),
                        "correlation_ids": _merge_ordered_unique(
                            existing.correlation_ids, item.correlation_ids
                        ),
                        "evidence_paths": _merge_ordered_unique(
                            existing.evidence_paths, item.evidence_paths
                        ),
                        "candidate_ids": _merge_ordered_unique(
                            existing.candidate_ids, item.candidate_ids
                        ),
                    }
                )
                imported.append(
                    _upsert_qa_item_in_tx(conn, campaign_id=state.campaign_id, item=merged)
                )
            else:
                seeded_attempts = max(item.attempts, state.attempts.get(item.item_id, 0))
                if seeded_attempts != item.attempts:
                    item = item.model_copy(update={"attempts": seeded_attempts})
                imported.append(
                    _upsert_qa_item_in_tx(conn, campaign_id=state.campaign_id, item=item)
                )
    return imported


def persist_run_record(
    store: FactoryStore,
    campaign_dir: Path,
    record: RunRecord,
) -> Path:
    """Persist RunRecord into qa_run_records SQLite table and runs.jsonl."""
    sanitized_dict = assert_strictly_redacted(
        json.loads(record.model_dump_json()), label=f"RunRecord:{record.run_id}"
    )
    clean_rec = RunRecord.model_validate(sanitized_dict)
    payload_json = json.dumps(sanitized_dict, sort_keys=True, ensure_ascii=False)

    with store.write_tx() as conn:
        conn.execute(
            """
            INSERT INTO qa_run_records (
                run_id, campaign_id, case_id, base_sha, candidate_sha, build_hash,
                lane, ui_variant, backend_mode, runtime_mode, emulated, passed, duration_ms,
                simulated_services, real_services, assertions, request_ids, artifact_paths,
                payload_json, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                passed=excluded.passed,
                duration_ms=excluded.duration_ms,
                assertions=excluded.assertions,
                request_ids=excluded.request_ids,
                artifact_paths=excluded.artifact_paths,
                payload_json=excluded.payload_json,
                finished_at=excluded.finished_at;
            """,
            (
                clean_rec.run_id,
                clean_rec.campaign_id,
                clean_rec.case_id,
                clean_rec.base_sha,
                clean_rec.candidate_sha,
                clean_rec.build_hash,
                clean_rec.lane,
                clean_rec.ui_variant,
                clean_rec.backend_mode,
                clean_rec.runtime_mode,
                int(clean_rec.emulated),
                int(clean_rec.passed),
                clean_rec.duration_ms,
                json.dumps(clean_rec.simulated_services),
                json.dumps(clean_rec.real_services),
                json.dumps(clean_rec.assertions),
                json.dumps(clean_rec.request_ids),
                json.dumps(clean_rec.artifact_paths),
                payload_json,
                ensure_utc(clean_rec.started_at).isoformat(),
                ensure_utc(clean_rec.finished_at).isoformat(),
            ),
        )

    runs_path = campaign_dir / "runs.jsonl"
    existing_lines: list[dict[str, Any]] = []
    if runs_path.is_file():
        for raw_line in runs_path.read_text(encoding="utf-8").splitlines():
            if raw_line.strip():
                try:
                    parsed = json.loads(raw_line)
                    if isinstance(parsed, dict) and parsed.get("run_id") != clean_rec.run_id:
                        existing_lines.append(parsed)
                except json.JSONDecodeError:
                    continue
    existing_lines.append(sanitized_dict)
    _atomic_write_text(
        runs_path,
        "\n".join(json.dumps(entry, ensure_ascii=False) for entry in existing_lines) + "\n",
    )
    return runs_path


def list_run_records(store: FactoryStore, campaign_id: str) -> list[RunRecord]:
    """Load persisted RunRecord rows for a campaign ordered by finished_at."""
    with store.read_tx() as conn:
        rows = conn.execute(
            """
            SELECT payload_json FROM qa_run_records
            WHERE campaign_id = ?
            ORDER BY finished_at ASC;
            """,
            (campaign_id,),
        ).fetchall()
    return [RunRecord.model_validate_json(str(r["payload_json"])) for r in rows]


_DIAGNOSTICS_API_CURSOR_NAME = "__diagnostics_api__"


def _load_cursors(
    store: FactoryStore,
    campaign_id: str,
    campaign_dir: Path,
) -> tuple[dict[str, LogCursor], set[str]]:
    cursors: dict[str, LogCursor] = {}
    seen_ids: set[str] = set()

    with store.read_tx() as conn:
        rows = conn.execute(
            "SELECT * FROM qa_log_cursors WHERE campaign_id = ?;",
            (campaign_id,),
        ).fetchall()
    for row in rows:
        fname = str(row["file_name"])
        for diag_id in json.loads(str(row["seen_diag_ids_json"] or "[]")):
            seen_ids.add(str(diag_id))
        if fname == _DIAGNOSTICS_API_CURSOR_NAME:
            continue
        dev = row["inode_dev"]
        ino = row["inode_ino"]
        inode = (int(dev), int(ino)) if dev is not None and ino is not None else None
        cursors[fname] = LogCursor(
            file_name=fname,
            inode=inode,
            byte_offset=int(row["byte_offset"] or 0),
        )

    json_path = campaign_dir / "log_cursors.json"
    if json_path.is_file():
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raw = {}
        if isinstance(raw, dict):
            for fname, entry in raw.items():
                if not isinstance(entry, dict):
                    continue
                json_off = int(entry.get("offset", entry.get("byte_offset", 0)) or 0)
                raw_inode = entry.get("inode")
                json_inode = (
                    (int(raw_inode[0]), int(raw_inode[1]))
                    if isinstance(raw_inode, list) and len(raw_inode) == 2
                    else None
                )
                prev = cursors.get(fname)
                if prev is None or json_off > prev.byte_offset:
                    cursors[fname] = LogCursor(
                        file_name=fname,
                        inode=(
                            json_inode
                            if json_inode is not None
                            else (prev.inode if prev else None)
                        ),
                        byte_offset=max(json_off, prev.byte_offset if prev else 0),
                    )
    return cursors, seen_ids


def _save_cursors(
    store: FactoryStore,
    campaign_id: str,
    campaign_dir: Path,
    cursors: Mapping[str, LogCursor],
    seen_ids: set[str],
) -> Path:
    now_iso = ensure_utc(utc_now()).isoformat()
    bounded_ids = sorted(seen_ids)[-2000:]
    seen_json = json.dumps(bounded_ids)

    with store.write_tx() as conn:
        for fname, cursor in cursors.items():
            cursor_key = f"{campaign_id}:{fname}"
            conn.execute(
                """
                INSERT INTO qa_log_cursors (
                    cursor_key, campaign_id, file_name, inode_dev, inode_ino,
                    byte_offset, file_size, seen_diag_ids_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cursor_key) DO UPDATE SET
                    inode_dev=excluded.inode_dev,
                    inode_ino=excluded.inode_ino,
                    byte_offset=excluded.byte_offset,
                    seen_diag_ids_json=excluded.seen_diag_ids_json,
                    updated_at=excluded.updated_at;
                """,
                (
                    cursor_key,
                    campaign_id,
                    fname,
                    cursor.inode[0] if cursor.inode is not None else None,
                    cursor.inode[1] if cursor.inode is not None else None,
                    cursor.byte_offset,
                    cursor.byte_offset,
                    seen_json,
                    now_iso,
                ),
            )
        if seen_ids and not cursors:
            cursor_key = f"{campaign_id}:{_DIAGNOSTICS_API_CURSOR_NAME}"
            conn.execute(
                """
                INSERT INTO qa_log_cursors (
                    cursor_key, campaign_id, file_name, inode_dev, inode_ino,
                    byte_offset, file_size, seen_diag_ids_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cursor_key) DO UPDATE SET
                    seen_diag_ids_json=excluded.seen_diag_ids_json,
                    updated_at=excluded.updated_at;
                """,
                (
                    cursor_key,
                    campaign_id,
                    _DIAGNOSTICS_API_CURSOR_NAME,
                    None,
                    None,
                    0,
                    0,
                    seen_json,
                    now_iso,
                ),
            )

    payload: dict[str, Any] = {}
    for fname, cursor in sorted(cursors.items()):
        payload[fname] = {
            "offset": cursor.byte_offset,
            "byte_offset": cursor.byte_offset,
            "inode": list(cursor.inode) if cursor.inode is not None else None,
        }
    cursors_path = campaign_dir / "log_cursors.json"
    _atomic_write_text(cursors_path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return cursors_path


def _classify_log_severity(rec: Mapping[str, Any]) -> Severity:
    blob = json.dumps(rec, ensure_ascii=False).lower()
    if any(marker in blob for marker in _P0_MARKERS):
        return "P0"
    status_raw = rec.get("status_code")
    status_code = int(status_raw) if isinstance(status_raw, (int, float)) else None
    kind = str(rec.get("kind") or "").lower()
    if (status_code is not None and status_code >= 500) or kind in {
        "uncaught_error",
        "unhandled_rejection",
        "service_health_alert",
        "abnormal_close",
        "sse_error",
        "routine_dispatch_error",
    }:
        return "P1"
    if (status_code is not None and status_code >= 400) or kind:
        return "P2"
    return "P3"


def _correlate_parent_item(
    store: FactoryStore,
    campaign_id: str,
    item: QAFailureItem,
) -> QAFailureItem:
    """Link frontend/UI failures to parent backend/watchdog items via request_id or [-5s, +5s]."""
    if item.parent_item_id is not None:
        return item
    is_frontend = item.subsystem in {"frontend", "ui", "browser"} or item.source == "ux"
    if not is_frontend:
        return item

    candidates = [
        cand
        for cand in list_qa_items(store, campaign_id)
        if cand.item_id != item.item_id
        and cand.subsystem not in {"frontend", "ui", "browser"}
        and cand.source != "ux"
    ]
    if not candidates:
        return item

    item_corrs = set(item.correlation_ids)
    matched_parent: QAFailureItem | None = None
    if item_corrs:
        for cand in candidates:
            if item_corrs & set(cand.correlation_ids):
                matched_parent = cand
                break

    if matched_parent is None:
        sig_lower = (item.normalized_signature + " " + item.summary).lower()
        api_drop_hint = any(
            tok in sig_lower
            for tok in (
                "err_connection_refused",
                "err_empty_response",
                "err_connection_reset",
                "sse_error",
                "http 50",
                "status 50",
            )
        )
        if api_drop_hint:
            item_ts = ensure_utc(item.last_seen_at)
            for cand in candidates:
                if abs((item_ts - ensure_utc(cand.last_seen_at)).total_seconds()) <= 5.0:
                    matched_parent = cand
                    break

    if matched_parent is None:
        return item

    updated = item.model_copy(update={"parent_item_id": matched_parent.item_id})
    return upsert_qa_item(store, campaign_id, updated)


def _scan_jsonl_secret_flags(
    path: Path,
    start_offset: int,
    max_entries: int,
) -> list[bool]:
    """Read-only in-memory scan of unread JSONL lines returning ONLY secret-presence booleans."""
    flags: list[bool] = []
    if not path.is_file():
        return flags
    with path.open("rb") as handle:
        handle.seek(max(0, start_offset))
        while len(flags) < max_entries:
            raw_line = handle.readline()
            if not raw_line or not raw_line.endswith(b"\n"):
                break
            if not raw_line.strip():
                continue
            try:
                parsed = json.loads(raw_line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                flags.append(_has_unredacted_secret_any(parsed))
    return flags


def _scan_unread_secret_flags(
    logs_dir: Path,
    cursors: Mapping[str, LogCursor] | None = None,
    max_entries_per_file: int = 5000,
) -> dict[str, list[bool]]:
    """Mirror read_sanitized_logs cursor slicing in memory to detect unredacted secrets."""
    flags_by_file: dict[str, list[bool]] = {}
    for fname in _LOG_FILES:
        active_path = logs_dir / fname
        prev = cursors.get(fname) if cursors is not None else None
        if not active_path.is_file():
            flags_by_file[fname] = []
            continue

        stat_res = active_path.stat()
        cur_inode = (stat_res.st_dev, stat_res.st_ino)
        file_flags: list[bool] = []

        if prev is not None and prev.inode is not None and prev.inode != cur_inode:
            rotated_path = active_path.with_suffix(active_path.suffix + ".1")
            if rotated_path.is_file():
                rot_stat = rotated_path.stat()
                if (
                    (rot_stat.st_dev, rot_stat.st_ino) == prev.inode
                    and prev.byte_offset < rot_stat.st_size
                ):
                    file_flags.extend(
                        _scan_jsonl_secret_flags(
                            rotated_path, prev.byte_offset, max_entries_per_file
                        )
                    )
            remaining = max(0, max_entries_per_file - len(file_flags))
            file_flags.extend(_scan_jsonl_secret_flags(active_path, 0, remaining))
        else:
            start_offset = 0
            if (
                prev is not None
                and prev.inode == cur_inode
                and prev.byte_offset <= stat_res.st_size
            ):
                start_offset = prev.byte_offset
            file_flags.extend(
                _scan_jsonl_secret_flags(active_path, start_offset, max_entries_per_file)
            )
        flags_by_file[fname] = file_flags
    return flags_by_file


def ingest_sanitized_logs(
    store: FactoryStore,
    state: CampaignState,
    *,
    logs_dir: Path | None,
    campaign_dir: Path,
    case_id: str = "CB-00",
    run_id: str | None = None,
    target_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Incrementally ingest JSONL logs (with .1 rotation) & optional diagnostics API."""
    cursors, seen_ids = _load_cursors(store, state.campaign_id, campaign_dir)
    ingested_count = 0
    ingested_request_ids: list[str] = []
    p0_items: list[QAFailureItem] = []

    if logs_dir is not None and logs_dir.is_dir():
        while True:
            prev_snapshot = {k: (v.inode, v.byte_offset) for k, v in cursors.items()}
            secret_flags_by_file = _scan_unread_secret_flags(
                logs_dir,
                cursors=cursors,
                max_entries_per_file=5000,
            )
            records_by_file, next_cursors = read_sanitized_logs(
                logs_dir,
                cursors=cursors,
                max_entries_per_file=5000,
            )

            # Preserve non-zero offsets only when the file does not exist (never on 0-byte truncate)
            reconciled_cursors: dict[str, LogCursor] = {}
            for fname, new_cur in next_cursors.items():
                prev_cur = cursors.get(fname)
                active_path = logs_dir / fname
                rotated_path = active_path.with_suffix(active_path.suffix + ".1")
                if (
                    prev_cur is not None
                    and prev_cur.byte_offset > 0
                    and not records_by_file.get(fname)
                    and not rotated_path.is_file()
                    and not active_path.is_file()
                ):
                    reconciled_cursors[fname] = prev_cur
                else:
                    reconciled_cursors[fname] = new_cur

            batch_total = 0
            for fname, entries in records_by_file.items():
                file_flags = secret_flags_by_file.get(fname, [])
                for idx, rec in enumerate(entries):
                    batch_total += 1
                    raw_has_secret = bool(file_flags[idx]) if idx < len(file_flags) else False
                    rec_id = str(rec.get("id") or "").strip()
                    if rec_id and rec_id in seen_ids:
                        continue
                    if not raw_has_secret and fname == "requests.jsonl":
                        status_code = rec.get("status_code")
                        if not isinstance(status_code, (int, float)) or int(status_code) < 500:
                            continue
                        req_id = str(rec.get("request_id") or "").strip()
                        if req_id and f"req:{req_id}" in seen_ids:
                            continue
                    if (
                        not raw_has_secret
                        and fname == "watchdog.jsonl"
                        and rec.get("all_ok") is True
                        and not rec.get("alerts")
                    ):
                        continue

                    if rec_id:
                        seen_ids.add(rec_id)
                    raw_source = str(rec.get("source") or fname.replace(".jsonl", "")).strip()
                    req_id = str(rec.get("request_id") or "").strip()
                    if req_id:
                        if (
                            fname != "frontend_errors.jsonl"
                            and raw_source not in {"frontend", "ui", "browser"}
                        ):
                            seen_ids.add(f"req:{req_id}")
                        if req_id not in ingested_request_ids:
                            ingested_request_ids.append(req_id)

                    kind = str(rec.get("kind") or "log_event").strip()
                    msg = str(rec.get("message") or "").strip()
                    path_val = str(rec.get("path") or "").strip()
                    method_val = str(rec.get("method") or "").strip()
                    status_val = rec.get("status_code")
                    raw_sig_parts = [p for p in (kind, method_val, path_val, msg) if p]
                    if status_val is not None and str(status_val) not in msg:
                        raw_sig_parts.append(f"http_{status_val}")
                    raw_sig = " ".join(raw_sig_parts) or fname
                    severity: Severity = "P0" if raw_has_secret else _classify_log_severity(rec)
                    qa_source: Literal["log", "diagnostics_api", "e2e", "ux", "watchdog"] = (
                        "watchdog"
                        if raw_source == "watchdog" or fname == "watchdog.jsonl"
                        else ("ux" if raw_source == "frontend" else "log")
                    )
                    ts_val: datetime | None = None
                    if isinstance(rec.get("ts"), str):
                        try:
                            ts_val = ensure_utc(datetime.fromisoformat(rec["ts"]))
                        except ValueError:
                            ts_val = None

                    item = record_failure_observation(
                        store,
                        state,
                        case_id=case_id,
                        subsystem=raw_source or "web",
                        raw_signature=raw_sig,
                        severity=severity,
                        summary=msg or f"{raw_source}: {kind}",
                        source=qa_source,
                        run_id=run_id,
                        correlation_ids=[req_id] if req_id else (),
                        initial_state="observed",
                        observed_at=ts_val,
                    )
                    ingested_count += 1
                    if item.severity == "P0":
                        p0_items.append(item)

            cursors = reconciled_cursors
            after_snapshot = {k: (v.inode, v.byte_offset) for k, v in cursors.items()}
            if batch_total < 5000 or after_snapshot == prev_snapshot:
                break

    if target_url:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            with httpx.Client(
                base_url=target_url.rstrip("/"),
                headers=headers,
                timeout=3.0,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                resp = client.get("/api/v1/diagnostics/failures", params={"limit": 200})
                if resp.status_code == 200:
                    data = resp.json()
                    failures = data.get("failures", []) if isinstance(data, dict) else []
                    for raw_rec in failures:
                        if not isinstance(raw_rec, dict):
                            continue
                        raw_has_secret = _has_unredacted_secret_any(raw_rec)
                        sanitized = assert_strictly_redacted(
                            raw_rec, label="diagnostics_api"
                        )
                        rec_id = str(sanitized.get("id") or "").strip()
                        if rec_id and rec_id in seen_ids:
                            continue
                        if rec_id:
                            seen_ids.add(rec_id)
                        req_id = str(sanitized.get("request_id") or "").strip()
                        if req_id:
                            seen_ids.add(f"req:{req_id}")
                            if req_id not in ingested_request_ids:
                                ingested_request_ids.append(req_id)
                        raw_source = str(sanitized.get("source") or "backend_http")
                        kind = str(sanitized.get("kind") or "diag_failure")
                        msg = str(sanitized.get("message") or "")
                        path_val = str(sanitized.get("path") or "")
                        raw_sig = " ".join(p for p in (kind, path_val, msg) if p) or kind
                        severity = (
                            "P0" if raw_has_secret else _classify_log_severity(sanitized)
                        )
                        item = record_failure_observation(
                            store,
                            state,
                            case_id=case_id,
                            subsystem=raw_source,
                            raw_signature=raw_sig,
                            severity=severity,
                            summary=msg or f"{raw_source}: {kind}",
                            source="diagnostics_api",
                            run_id=run_id,
                            correlation_ids=[req_id] if req_id else (),
                            initial_state="observed",
                        )
                        ingested_count += 1
                        if item.severity == "P0":
                            p0_items.append(item)
        except (httpx.HTTPError, json.JSONDecodeError, OSError):
            pass

    # Post-pass cross-file correlation so frontend errors link to backend items regardless of order
    for qa_item in list_qa_items(store, state.campaign_id):
        if (
            qa_item.parent_item_id is None
            and (qa_item.subsystem in {"frontend", "ui", "browser"} or qa_item.source == "ux")
        ):
            _correlate_parent_item(store, state.campaign_id, qa_item)

    _save_cursors(store, state.campaign_id, campaign_dir, cursors, seen_ids)
    sync_failures_jsonl_from_store(store, state.campaign_id, campaign_dir)

    halted_p0 = bool(p0_items)
    if halted_p0:
        halt_reason = "; ".join(f"{it.item_id}:{it.summary}" for it in p0_items)
        new_state = state.model_copy(
            update={
                "status": "halted_p0",
                "p0_halt_reason": halt_reason,
                "updated_at": utc_now(),
            }
        )
        save_campaign_state(campaign_dir, new_state, store=store)

    return {
        "ingested_count": ingested_count,
        "ingested_request_ids": ingested_request_ids,
        "halted_p0": halted_p0,
        "p0_items": [it.item_id for it in p0_items],
        "cursors": {k: v.byte_offset for k, v in cursors.items()},
    }


def _is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    if not proc_cmdline.exists():
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def resume_campaign(
    campaign_dir: Path,
    *,
    repo_root: Path | None = None,
    logs_dir: Path | None = None,
) -> tuple[CampaignState, dict[str, Any]]:
    """Crash-safe resume: preserve attempts/leases/cursors and ingest rotated log tails."""
    safe_dir = assert_safe_mutation_path(campaign_dir, repo_root=repo_root)
    campaign_file = safe_dir / "campaign.json"
    if not campaign_file.is_file():
        raise FileNotFoundError(f"Missing campaign.json in {safe_dir}")
    state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))

    # Validate target_url and runtime DB env isolation before proceeding
    _validate_runtime_db_env(repo_root=repo_root)
    store = open_campaign_store(safe_dir, state, repo_root=repo_root)
    import_failures_jsonl_into_store(store, state, safe_dir)

    # Reconcile worker PIDs and FactoryStore leases without resetting attempts or synthetic leases
    reconciled_pids: dict[str, int] = {}
    reconciled_leases: dict[str, str] = dict(state.active_leases)
    expired_leases: list[str] = []
    reconciled_in_repair_ids: set[str] = set()

    for item_id, pid in state.active_worker_pids.items():
        if _is_pid_alive(pid):
            reconciled_pids[item_id] = pid
        else:
            lease_id = reconciled_leases.get(item_id)
            if lease_id:
                latest_lease = store.get_latest_lease(f"fb-{item_id}") or store.get_latest_lease(
                    item_id
                )
                if latest_lease is not None and latest_lease.lease_id == lease_id:
                    if latest_lease.status == "active":
                        with contextlib.suppress(Exception):
                            store.release_lease(latest_lease.lease_id, latest_lease.generation)
                    reconciled_leases.pop(item_id, None)
                    expired_leases.append(lease_id)

            qa_item = get_qa_item(store, state.campaign_id, item_id)
            if qa_item is not None and qa_item.state == "in_repair":
                reconciled_in_repair_ids.add(item_id)
                item_attempts = max(qa_item.attempts, state.attempts.get(item_id, 0))
                if item_attempts >= state.max_attempts_per_item:
                    transition_qa_item_state(
                        store,
                        state.campaign_id,
                        item_id,
                        "parked",
                        next_diagnostic=(
                            "Worker crashed after exhausting max_attempts; "
                            "needs manual diagnosis."
                        ),
                    )
                else:
                    transition_qa_item_state(store, state.campaign_id, item_id, "reproduced")

    now_utc = ensure_utc(utc_now())
    for qa_item in list_qa_items(store, state.campaign_id, states=("in_repair",)):
        if qa_item.item_id in reconciled_pids or qa_item.item_id in reconciled_in_repair_ids:
            continue
        latest_lease = store.get_latest_lease(
            qa_item.factory_item_id or f"fb-{qa_item.item_id}"
        ) or store.get_latest_lease(qa_item.item_id)
        lease_orphaned = (
            latest_lease is None
            or latest_lease.status != "active"
            or ensure_utc(latest_lease.expiry) <= now_utc
            or qa_item.item_id not in state.active_worker_pids
        )
        if lease_orphaned:
            if latest_lease is not None and latest_lease.status == "active":
                with contextlib.suppress(Exception):
                    store.release_lease(latest_lease.lease_id, latest_lease.generation)
                if latest_lease.lease_id not in expired_leases:
                    expired_leases.append(latest_lease.lease_id)
            reconciled_leases.pop(qa_item.item_id, None)
            item_attempts = max(qa_item.attempts, state.attempts.get(qa_item.item_id, 0))
            if item_attempts >= state.max_attempts_per_item:
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    qa_item.item_id,
                    "parked",
                    next_diagnostic=(
                        "Orphaned in_repair item exhausted max_attempts; "
                        "needs manual diagnosis."
                    ),
                )
            else:
                transition_qa_item_state(store, state.campaign_id, qa_item.item_id, "reproduced")

    # Resolve logs_dir from parameter or baseline.json active_log_summary.logs_dir
    resolved_logs_dir = logs_dir
    if resolved_logs_dir is None:
        baseline_file = safe_dir / "baseline.json"
        if baseline_file.is_file():
            try:
                base_data = json.loads(baseline_file.read_text(encoding="utf-8"))
                raw_logs_dir = (base_data.get("active_log_summary") or {}).get("logs_dir")
                if isinstance(raw_logs_dir, str) and raw_logs_dir.strip():
                    resolved_logs_dir = Path(raw_logs_dir)
            except (json.JSONDecodeError, OSError):
                pass

    ingest_info = ingest_sanitized_logs(
        store,
        state,
        logs_dir=resolved_logs_dir,
        campaign_dir=safe_dir,
        case_id="CB-00",
    )

    # Reload campaign.json after ingest_sanitized_logs so halted_p0 / p0_halt_reason is preserved
    latest_state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
    all_items = list_qa_items(store, latest_state.campaign_id)
    open_p0 = [
        it
        for it in all_items
        if it.severity == "P0" and it.state not in {"accepted_qa", "parked"}
    ]

    # Preserve all attempt counters & sync from SQLite qa_items
    merged_attempts = dict(latest_state.attempts)
    for item in all_items:
        if item.attempts > 0:
            merged_attempts[item.item_id] = max(merged_attempts.get(item.item_id, 0), item.attempts)

    preserved_status = latest_state.status
    preserved_p0_reason = latest_state.p0_halt_reason
    if ingest_info.get("halted_p0") and preserved_status != "halted_p0":
        preserved_status = "halted_p0"
        if not preserved_p0_reason:
            preserved_p0_reason = "; ".join(f"{it.item_id}:{it.summary}" for it in open_p0) or (
                "P0 incident detected during log ingestion"
            )

    updated_state = latest_state.model_copy(
        update={
            "status": preserved_status,
            "p0_halt_reason": preserved_p0_reason,
            "attempts": merged_attempts,
            "active_leases": reconciled_leases,
            "active_worker_pids": reconciled_pids,
            "last_requested_command": "resume",
            "updated_at": utc_now(),
        }
    )
    save_campaign_state(safe_dir, updated_state, store=store)
    sync_failures_jsonl_from_store(store, updated_state.campaign_id, safe_dir)

    return updated_state, {
        "expired_leases": expired_leases,
        "ingested_from_logs": ingest_info["ingested_count"],
        "halted_p0": updated_state.status == "halted_p0",
        "cursors": ingest_info["cursors"],
        "preserved_attempts": merged_attempts,
        "preserved_leases": reconciled_leases,
    }


def compute_same_sha_passes(
    runs: Sequence[RunRecord],
    sha: str,
) -> int:
    """Count consecutive green runs on `sha` from the tail of `runs`."""
    count = 0
    for rec in reversed(runs):
        run_sha = rec.candidate_sha or rec.base_sha
        if run_sha != sha:
            continue
        if rec.passed:
            count += 1
        else:
            break
    return count


__all__ = [
    "assert_strictly_redacted",
    "compute_same_sha_passes",
    "get_qa_item",
    "import_failures_jsonl_into_store",
    "ingest_sanitized_logs",
    "list_qa_items",
    "list_run_records",
    "normalize_failure_signature",
    "open_campaign_store",
    "persist_run_record",
    "record_failure_observation",
    "record_item_probe_outcome",
    "resolve_campaign_db_path",
    "resume_campaign",
    "save_campaign_state",
    "sync_campaign_record",
    "sync_failures_jsonl_from_store",
    "transition_qa_item_state",
    "upsert_qa_item",
]
