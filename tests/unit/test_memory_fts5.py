"""Unit tests for compartmentalized FTS5 memory, ACLs, TTL, redaction, 409, and audit chain."""

from __future__ import annotations

import json
import os
import random
import sqlite3
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from src.storage.audit_chain import (
    GENESIS_PREV_HASH,
    append_chained_audit_row,
    ensure_workspace_audit_schema,
    verify_chain,
)
from src.storage.memory import (
    PINNED_MAX_BYTES,
    PINNED_MAX_LINES,
    RECALL_MAX_CHARS,
    MemoryAccessContext,
    MemoryConflictError,
    MemoryNotFoundError,
    MemoryPermissionError,
    MemoryStore,
    MemoryValidationError,
    _fast_contains_unredacted_secret_strict,
    _normalize_probe,
    _probe_json_container_is_clean,
    _QuoteEnclosureTracker,
    _redact_core,
    build_fts5_query,
    redact_memory_text,
)
from src.storage.redaction import contains_unredacted_secret_strict


@pytest.mark.n1
def test_fts5_tokenchars_and_safe_query_builder(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "mem.sqlite3")
    ctx = MemoryAccessContext(user_id="alice", actor_role="Operator")

    store.create_memory(
        scope="user",
        scope_id="alice",
        kind="source_reference",
        title="Work Order Dispatch",
        content="Inspect check valve on WO-2026500. Also calibrate TT-402B at 4-20mA 1/4 turn.",
        tags="CN-N1200 maintenance",
    )

    # Trailing period in content and query must match industrial ID WO-2026500 cleanly
    assert len(store.search_memories(ctx, "WO-2026500.")) == 1
    assert len(store.search_memories(ctx, "WO-2026500")) == 1
    assert len(store.search_memories(ctx, "Check WO-2026500.")) == 1
    assert len(store.search_memories(ctx, "TT-402B")) == 1
    assert len(store.search_memories(ctx, "4-20mA")) == 1
    assert len(store.search_memories(ctx, "1/4")) == 1
    assert len(store.search_memories(ctx, "CN-N1200")) == 1

    # FTS5 boolean/negation syntax injection must never raise OperationalError
    for tricky in ("-WO-2026500", "NOT OR AND NEAR", 'foo "bar" (baz)', "--- ///", "a-b:c"):
        res = store.search_memories(ctx, tricky)
        assert isinstance(res, list)

    assert build_fts5_query("Check WO-2026500.") == '"Check" "WO-2026500"'
    assert build_fts5_query("--- ...") is None
    store.close()


@pytest.mark.n1
def test_memory_five_acl_scopes_sql_isolation(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "acl.sqlite3")

    m_user_a = store.create_memory(
        scope="user",
        scope_id="alice",
        kind="preference",
        title="Alice pref",
        content="Alice prefers concise bullet summaries.",
    )
    m_user_b = store.create_memory(
        scope="user",
        scope_id="bob",
        kind="preference",
        title="Bob pref",
        content="Bob prefers long prose reports.",
    )
    m_role = store.create_memory(
        scope="agent_role",
        scope_id="ops_engineer",
        kind="source_reference",
        title="Ops manual",
        content="Check line pressure gauges first.",
    )
    m_thread = store.create_memory(
        scope="thread",
        scope_id="thr_123",
        kind="source_reference",
        title="Thread note",
        content="Pump #3 bearing temp checked.",
    )
    # Alias 'project' and 'project/area' both normalize to 'project_area'
    m_proj = store.create_memory(
        scope="project",
        scope_id="plant_north",
        kind="source_reference",
        title="North Wing",
        content="North wing boiler specs.",
    )
    assert m_proj["scope"] == "project_area"
    m_org = store.create_memory(
        scope="org_approved",
        scope_id="global",
        kind="approved_procedure",
        title="Lockout Tagout",
        content="Verify zero energy state before maintenance.",
        actor_role="Manager",
    )

    ctx_alice = MemoryAccessContext(user_id="alice", include_org_approved=True)
    alice_ids = {item["id"] for item in store.list_memories(ctx_alice)}
    assert m_user_a["id"] in alice_ids
    assert m_org["id"] in alice_ids
    assert m_user_b["id"] not in alice_ids
    assert m_role["id"] not in alice_ids
    assert m_thread["id"] not in alice_ids
    assert m_proj["id"] not in alice_ids

    # get_memory enforces SQL WHERE isolation
    assert store.get_memory(m_user_b["id"], access_ctx=ctx_alice) is None
    assert store.get_memory(m_user_a["id"], access_ctx=ctx_alice) is not None

    # Role, thread, project_area scopes visible only to matching context
    ctx_ops = MemoryAccessContext(
        user_id="alice",
        agent_role="ops_engineer",
        thread_id="thr_123",
        project_area="plant_north",
        include_org_approved=False,
    )
    ops_ids = {item["id"] for item in store.list_memories(ctx_ops)}
    assert ops_ids == {m_user_a["id"], m_role["id"], m_thread["id"], m_proj["id"]}

    # Empty fail-closed context returns nothing
    ctx_empty = MemoryAccessContext(include_org_approved=False)
    assert store.list_memories(ctx_empty) == []

    # Cross-user update/delete fails with MemoryPermissionError (PermissionError)
    with pytest.raises(MemoryPermissionError):
        store.update_memory(
            m_user_b["id"],
            expected_revision=1,
            access_ctx=ctx_alice,
            content="Tamper",
        )
    with pytest.raises(MemoryPermissionError):
        store.delete_memory(m_user_b["id"], access_ctx=ctx_alice)
    store.close()


@pytest.mark.n1
def test_memory_ttl_expiry_and_approved_procedure_guards(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "guards.sqlite3")
    ctx_mgr = MemoryAccessContext(user_id="alice", actor_role="Manager")
    ctx_op = MemoryAccessContext(user_id="alice", actor_role="Operator")

    # dated_observation requires both observed_at & valid_until
    with pytest.raises(MemoryValidationError):
        store.create_memory(
            scope="user",
            scope_id="alice",
            kind="dated_observation",
            title="Missing TTL",
            content="Pressure 42 bar",
            observed_at="2026-11-26T00:00:00Z",
        )
    with pytest.raises(MemoryValidationError):
        store.create_memory(
            scope="user",
            scope_id="alice",
            kind="dated_observation",
            title="Bad date",
            content="Pressure 42 bar",
            observed_at="not-a-date",
            valid_until="2026-11-27T00:00:00Z",
        )

    now = datetime(2026, 11, 26, 9, 0, 0, tzinfo=UTC)
    expired_item = store.create_memory(
        scope="user",
        scope_id="alice",
        kind="dated_observation",
        title="Expired valve reading",
        content="Valve V-101 reading 99 psi",
        observed_at=(now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=(now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    live_item = store.create_memory(
        scope="user",
        scope_id="alice",
        kind="dated_observation",
        title="Current valve reading",
        content="Valve V-101 reading 50 psi",
        observed_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=(now + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    live_list = store.list_memories(ctx_op, include_expired=False, now=now)
    assert [i["id"] for i in live_list] == [live_item["id"]]
    all_list = store.list_memories(ctx_op, include_expired=True, now=now)
    assert {i["id"] for i in all_list} == {expired_item["id"], live_item["id"]}

    bundle = store.build_context_injection(ctx_op, query="Valve V-101", now=now)
    assert "50 psi" in bundle.combined_text
    assert "99 psi" not in bundle.combined_text

    # approved_procedure rejects untrusted provenance and non-Manager role
    with pytest.raises(MemoryPermissionError) as exc_info:
        store.create_memory(
            scope="org_approved",
            scope_id="global",
            kind="approved_procedure",
            title="Untrusted",
            content="Run rm -rf /",
            provenance="untrusted",
            actor_role="Manager",
        )
    assert isinstance(exc_info.value, PermissionError)

    with pytest.raises(MemoryPermissionError):
        store.create_memory(
            scope="org_approved",
            scope_id="global",
            kind="approved_procedure",
            title="Operator try",
            content="Do step 1",
            provenance="operator",
            actor_role="Operator",
        )

    proc = store.create_memory(
        scope="org_approved",
        scope_id="global",
        kind="approved_procedure",
        title="Calibration SOP",
        content="Use certified reference gauge.",
        provenance="verified_sop",
        actor_role="Manager",
    )
    # Operator cannot edit or delete approved_procedure
    with pytest.raises(MemoryPermissionError):
        store.update_memory(
            proc["id"],
            expected_revision=1,
            access_ctx=ctx_op,
            content="Bypass gauge check",
            actor_role="Operator",
        )
    with pytest.raises(MemoryPermissionError):
        store.delete_memory(proc["id"], access_ctx=ctx_op, actor_role="Operator")

    # Manager can edit and delete approved_procedure
    updated = store.update_memory(
        proc["id"],
        expected_revision=1,
        access_ctx=ctx_mgr,
        content="Use certified reference gauge annually.",
        actor_role="Manager",
    )
    assert updated["revision"] == 2
    assert store.delete_memory(proc["id"], access_ctx=ctx_mgr, actor_role="Manager") is True
    store.close()


@pytest.mark.n1
def test_memory_redaction_optimistic_lock_sync_delete_and_0600_export(tmp_path: Path) -> None:
    db_path = tmp_path / "redaction.sqlite3"
    store = MemoryStore(db_path)
    ctx = MemoryAccessContext(user_id="alice", actor_role="Operator")

    secret_token = "sk-live-supersecret-987654321"
    secret_pw = "MySecretPass99!"
    text, redactions = redact_memory_text(
        f"Use Bearer {secret_token} and "
        f"https://alice:{secret_pw}@api.local/v1 api_key={secret_token}"
    )
    assert redactions >= 3
    assert secret_token not in text
    assert secret_pw not in text
    assert f"redacted {len(secret_token)} chars" in text
    assert f"redacted {len(secret_pw)} chars" in text

    # Re-redacting already redacted text is idempotent
    text_again, count_again = redact_memory_text(text)
    assert text_again == text
    assert count_again == 0

    # Inline bearer=..., foo_secretkey=..., and URL query '&' boundaries
    bearer_out, bearer_count = redact_memory_text("Set bearer=supersecret123")
    assert bearer_out == "Set bearer=redacted 14 chars"
    assert bearer_count == 1
    assert redact_memory_text(bearer_out) == (bearer_out, 0)

    quoted_bearer_out, quoted_bearer_count = redact_memory_text('bearer="supersecret123"')
    assert quoted_bearer_out == 'bearer="redacted 14 chars"'
    assert quoted_bearer_count == 1

    url_out, url_count = redact_memory_text(
        "https://api.local/hook?api_key=secret123&mode=fast"
    )
    assert url_out == "https://api.local/hook?api_key=redacted 9 chars&mode=fast"
    assert url_count == 1
    assert redact_memory_text(url_out) == (url_out, 0)

    sk_out, sk_count = redact_memory_text("foo_secretkey=abc12345")
    assert sk_out == "foo_secretkey=redacted 8 chars"
    assert sk_count == 1

    created = store.create_memory(
        scope="user",
        scope_id="alice",
        kind="preference",
        title="API Auth Note",
        content=f"Connect with password={secret_pw} and token sk-abcd1234efgh5678",
    )
    assert secret_pw not in created["content"]
    assert "sk-abcd1234efgh5678" not in created["content"]
    assert f"redacted {len(secret_pw)} chars" in created["content"]
    assert f"redacted {len('sk-abcd1234efgh5678')} chars" in created["content"]

    # Optimistic locking -> MemoryConflictError on stale revision
    upd = store.update_memory(
        created["id"],
        expected_revision=1,
        access_ctx=ctx,
        content="Updated safe preference",
    )
    assert upd["revision"] == 2
    with pytest.raises(MemoryConflictError):
        store.update_memory(
            created["id"],
            expected_revision=1,
            access_ctx=ctx,
            content="Stale write",
        )

    # Export to file with strict 0600 permissions & zero secret leaks
    export_md = tmp_path / "export" / "memories.md"
    store.export_to_file(export_md, ctx, fmt="md")
    assert stat.S_IMODE(os.stat(export_md).st_mode) == 0o600
    md_body = export_md.read_text(encoding="utf-8")
    assert "Updated safe preference" in md_body
    assert secret_pw not in md_body

    # Symlink export target must be rejected
    symlink_target = tmp_path / "export" / "link.md"
    symlink_target.symlink_to(export_md)
    with pytest.raises(MemoryPermissionError):
        store.export_to_file(symlink_target, ctx, fmt="md")

    # Synchronized delete purges both memory_items and memory_fts_docsize
    raw_conn = sqlite3.connect(str(db_path))
    seq_row = raw_conn.execute(
        "SELECT seq FROM memory_items WHERE id = ?", (created["id"],)
    ).fetchone()
    assert seq_row is not None
    seq_id = int(seq_row[0])
    assert raw_conn.execute("SELECT 1 FROM memory_fts_docsize WHERE id = ?", (seq_id,)).fetchone()
    raw_conn.close()

    assert store.delete_memory(created["id"], access_ctx=ctx) is True
    with pytest.raises(MemoryNotFoundError):
        store.delete_memory(created["id"], access_ctx=ctx)

    raw_conn = sqlite3.connect(str(db_path))
    assert (
        raw_conn.execute("SELECT 1 FROM memory_items WHERE id = ?", (created["id"],)).fetchone()
        is None
    )
    assert (
        raw_conn.execute("SELECT 1 FROM memory_fts_docsize WHERE id = ?", (seq_id,)).fetchone()
        is None
    )
    raw_conn.execute("INSERT INTO memory_fts(memory_fts) VALUES('integrity-check')")
    raw_conn.close()
    store.close()


@pytest.mark.n1
def test_context_builder_caps_150_lines_16kb_and_4_plus_4_6000_chars(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "caps.sqlite3")
    ctx = MemoryAccessContext(user_id="alice", actor_role="Manager")

    # Create 200 preference items (2 lines each = 400 lines > 150 lines)
    for i in range(60):
        store.create_memory(
            scope="user",
            scope_id="alice",
            kind="preference",
            title=f"Preference {i}",
            content=("Line A " + ("x" * 200) + "\nLine B\nLine C"),
        )

    # Create 10 source_reference items matching "boiler"
    for i in range(10):
        store.create_memory(
            scope="user",
            scope_id="alice",
            kind="source_reference",
            title=f"Boiler doc {i}",
            content=f"Boiler telemetry record {i} " + ("d" * 1000),
        )

    passages = [f"Thread passage {i}: " + ("p" * 1000) for i in range(8)]
    bundle = store.build_context_injection(ctx, query="boiler", thread_passages=passages)

    assert len(bundle.pinned_text.splitlines()) <= PINNED_MAX_LINES
    assert len(bundle.pinned_text.encode("utf-8")) <= PINNED_MAX_BYTES
    assert bundle.recalled_count <= 4
    assert bundle.passage_count <= 4
    assert len(bundle.recall_text) <= RECALL_MAX_CHARS
    assert "authority=advisory_only" in bundle.pinned_text
    assert "authority=advisory_only" in bundle.recall_text
    store.close()


@pytest.mark.n1
def test_audit_chain_append_only_triggers_and_tamper_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.sqlite3"
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    ensure_workspace_audit_schema(conn)

    conn.execute("BEGIN IMMEDIATE;")
    r1 = append_chained_audit_row(
        conn,
        actor="operator",
        action="vault.create",
        entity_type="vault_secret",
        entity_id="vlt_1",
        detail={"api_key": "raw-secret-must-be-scrubbed", "domain": "erp.local"},
    )
    r2 = append_chained_audit_row(
        conn,
        actor="operator",
        action="approval.resolve",
        entity_type="approval",
        entity_id="apr_1",
        decision="allowed_once",
        detail={"bot_id": "bot_chief"},
    )
    r3 = append_chained_audit_row(
        conn,
        actor="operator",
        action="settings.update",
        entity_type="settings",
        entity_id="default",
        detail={"keys": ["theme"]},
    )
    conn.execute("COMMIT;")

    assert r1["prev_hash"] == GENESIS_PREV_HASH
    assert r2["prev_hash"] == r1["entry_hash"]
    assert r3["prev_hash"] == r2["entry_hash"]
    assert "raw-secret-must-be-scrubbed" not in str(r1["detail"])

    rows = conn.execute("SELECT * FROM workspace_audit_log ORDER BY seq ASC").fetchall()
    ok = verify_chain(rows)
    assert ok == {
        "valid": True,
        "checked": 3,
        "broken_seq": None,
        "reason": None,
        "head_hash": r3["entry_hash"],
    }

    # Append-only triggers block UPDATE and DELETE
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE workspace_audit_log SET decision = 'tampered' WHERE seq = 2")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM workspace_audit_log WHERE seq = 2")

    # Drop triggers on test DB to simulate raw SQLite file tampering
    conn.execute("DROP TRIGGER trg_workspace_audit_log_no_update")
    conn.execute("DROP TRIGGER trg_workspace_audit_log_no_delete")

    # 1. Field tamper
    dict_rows = [dict(r) for r in rows]
    tampered_field = [dict(r) for r in dict_rows]
    tampered_field[1]["decision"] = "tampered"
    res_field = verify_chain(tampered_field)
    assert res_field["valid"] is False
    assert res_field["broken_seq"] == 2
    assert res_field["reason"] == "entry_hash_mismatch"

    # 2. Genesis prev_hash tamper
    tampered_genesis = [dict(r) for r in dict_rows]
    tampered_genesis[0]["prev_hash"] = "f" * 64
    res_gen = verify_chain(tampered_genesis)
    assert res_gen["valid"] is False
    assert res_gen["broken_seq"] == 1
    assert res_gen["reason"] == "prev_hash_mismatch"

    # 3. Middle deletion -> sequence_gap
    res_mid = verify_chain([dict_rows[0], dict_rows[2]])
    assert res_mid["valid"] is False
    assert res_mid["broken_seq"] == 2
    assert res_mid["reason"] == "sequence_gap"

    # 4. Head deletion -> sequence_gap at seq 1
    res_head = verify_chain([dict_rows[1], dict_rows[2]])
    assert res_head["valid"] is False
    assert res_head["broken_seq"] == 1
    assert res_head["reason"] == "sequence_gap"

    # 5. Tail deletion -> detected with expected_count
    res_tail = verify_chain([dict_rows[0], dict_rows[1]], expected_count=3)
    assert res_tail["valid"] is False
    assert res_tail["broken_seq"] == 3
    assert res_tail["reason"] == "tail_truncation"

    # 6. Corrupt JSON
    tampered_json = [dict(r) for r in dict_rows]
    tampered_json[2]["detail_json"] = "{corrupt"
    res_json = verify_chain(tampered_json)
    assert res_json["valid"] is False
    assert res_json["broken_seq"] == 3
    assert res_json["reason"] == "corrupt_detail_json"
    conn.close()


@pytest.mark.n1
def test_memory_redaction_enclosed_kv_auth_header_and_thread_passages(tmp_path: Path) -> None:
    for raw, expected in (
        ("(token=abc123)", "(token=redacted 6 chars)"),
        ("[api_key=secret123]", "[api_key=redacted 9 chars]"),
        ("{password=secret123}", "{password=redacted 9 chars}"),
        ("(bearer=secret123)", "(bearer=redacted 9 chars)"),
        ("Authorization: Bearer tok", "Authorization: Bearer redacted 3 chars"),
        ("Authorization: Basic dXNlcjpwYXNz", "Authorization: Basic redacted 12 chars"),
    ):
        scrubbed, count = redact_memory_text(raw)
        assert scrubbed == expected
        assert count == 1
        assert redact_memory_text(scrubbed) == (expected, 0)

    raw_auth, raw_auth_count = redact_memory_text("Authorization: rawsecret123")
    assert raw_auth == "Authorization: redacted 12 chars"
    assert raw_auth_count == 1
    assert redact_memory_text(raw_auth) == (raw_auth, 0)

    store = MemoryStore(tmp_path / "enclosed.sqlite3")
    ctx = MemoryAccessContext(user_id="alice", actor_role="Operator")
    bundle = store.build_context_injection(
        ctx,
        thread_passages=["User pasted (token=abc123) earlier"],
    )
    assert "(token=redacted 6 chars)" in bundle.recall_text
    assert "abc123" not in bundle.combined_text
    assert bundle.passage_count == 1
    store.close()


@pytest.mark.n1
def test_memory_redaction_auth_equals_delimiter_preservation_and_crafted_bypass_prevention() -> (
    None
):
    # '=' separator Authorization=Bearer / authorization=Basic & preserved delimiters/quotes
    for raw, expected, expected_count in (
        ("Authorization=Bearer tok", "Authorization=redacted 6 chars redacted 3 chars", 2),
        (
            "authorization=Basic dXNlcjpwYXNz",
            "authorization=redacted 5 chars redacted 12 chars",
            2,
        ),
        ("(Authorization: Bearer tok)", "(Authorization: Bearer redacted 3 chars)", 1),
        ('{"Authorization": "Bearer tok"}', '{"Authorization": "Bearer redacted 3 chars"}', 1),
        ('Authorization: "Bearer tok"', 'Authorization: "Bearer redacted 3 chars"', 1),
    ):
        scrubbed, count = redact_memory_text(raw)
        assert scrubbed == expected
        assert count == expected_count
        assert redact_memory_text(scrubbed) == (expected, 0)

    # Crafted 'redacted N chars...' bypasses must never leak REAL_SECRET
    crafted_inputs = (
        "token=redacted 6 chars_REAL_SECRET",
        "Authorization: Bearer redacted 3 chars_REAL_SECRET",
        "token=redacted 6 chars)REAL_SECRET",
        "token=redacted 6 chars]REAL_SECRET",
        "token=redacted 6 chars}REAL_SECRET",
        "Bearer redacted 3 chars)REAL_SECRET",
        "token=[REDACTED])REAL_SECRET",
        "Bearer [REDACTED])REAL_SECRET",
    )
    for crafted in crafted_inputs:
        try:
            scrubbed, count = redact_memory_text(crafted)
        except MemoryValidationError:
            continue
        assert "REAL_SECRET" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)


@pytest.mark.n1
def test_org_approved_manager_role_enforced_across_all_kinds(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "org_acl.sqlite3")
    ctx_op = MemoryAccessContext(user_id="bob", actor_role="Operator")
    ctx_mgr = MemoryAccessContext(user_id="mgr", actor_role="Manager")
    now = datetime(2026, 11, 26, 9, 0, 0, tzinfo=UTC)

    kinds_kwargs: list[tuple[str, dict[str, str]]] = [
        ("preference", {}),
        (
            "dated_observation",
            {
                "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "valid_until": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ),
        ("source_reference", {}),
        ("approved_procedure", {}),
    ]

    for kind, extra in kinds_kwargs:
        # Operator cannot create org_approved of any kind
        with pytest.raises(MemoryPermissionError):
            store.create_memory(
                scope="org_approved",
                scope_id="global",
                kind=kind,
                title=f"Org {kind}",
                content="Should fail for Operator",
                actor_role="Operator",
                **extra,
            )

        item = store.create_memory(
            scope="org_approved",
            scope_id="global",
            kind=kind,
            title=f"Org {kind}",
            content="Manager baseline",
            actor_role="Manager",
            **extra,
        )

        # Operator cannot update or delete org_approved of any kind
        with pytest.raises(MemoryPermissionError):
            store.update_memory(
                item["id"],
                expected_revision=1,
                access_ctx=ctx_op,
                content="Hijacked by Operator",
                actor_role="Operator",
            )
        with pytest.raises(MemoryPermissionError):
            store.delete_memory(item["id"], access_ctx=ctx_op, actor_role="Operator")

        # Manager succeeds on both update and delete
        updated = store.update_memory(
            item["id"],
            expected_revision=1,
            access_ctx=ctx_mgr,
            content="Updated by Manager",
            actor_role="Manager",
        )
        assert updated["revision"] == 2
        assert store.delete_memory(item["id"], access_ctx=ctx_mgr, actor_role="Manager") is True

    store.close()


@pytest.mark.n1
def test_memory_redaction_json_kv_quoted_bearer_unbounded_tail_and_comma_semicolon() -> None:
    # 1. JSON KV secrets, quoted Bearer/Basic, nested enclosures, and directives (idempotent)
    exact_cases: tuple[tuple[str, str, int], ...] = (
        ('{"token": "REAL_SECRET"}', '{"token": "redacted 11 chars"}', 1),
        ('{"api_key": "REAL_SECRET"}', '{"api_key": "redacted 11 chars"}', 1),
        ('{"password": "REAL_SECRET"}', '{"password": "redacted 11 chars"}', 1),
        ('{"Authorization": "rawsecret123"}', '{"Authorization": "redacted 12 chars"}', 1),
        ('{"Authorization": "Bearer tok"}', '{"Authorization": "Bearer redacted 3 chars"}', 1),
        (
            '{"token": "REAL_SECRET", "next": "ok"}',
            '{"token": "redacted 11 chars", "next": "ok"}',
            1,
        ),
        ('{"token": "[REDACTED]"}', '{"token": "redacted 10 chars"}', 1),
        ('{"token": "[REDACTED]", "x": 1}', '{"token": "redacted 10 chars", "x": 1}', 1),
        ('Authorization: Bearer "REAL_SECRET"', 'Authorization: Bearer "redacted 11 chars"', 1),
        ("Authorization: Bearer 'REAL_SECRET'", "Authorization: Bearer 'redacted 11 chars'", 1),
        ('Authorization: Basic "dXNlcjpwYXNz"', 'Authorization: Basic "redacted 12 chars"', 1),
        ("((token=abc123))", "((token=redacted 6 chars))", 1),
        ("[(Authorization: Bearer tok)]", "[(Authorization: Bearer redacted 3 chars)]", 1),
        ("Bearer tok, next", "Bearer redacted 3 chars, next", 1),
        ("Authorization: Bearer tok, next", "Authorization: Bearer redacted 3 chars, next", 1),
        ("Bearer tok;realm=foo", "Bearer redacted 3 chars;realm=foo", 1),
        (
            "Authorization: Bearer tok;realm=foo",
            "Authorization: Bearer redacted 3 chars;realm=foo",
            1,
        ),
        ('{"auth":"Bearer tok","a":1}', '{"auth":"Bearer redacted 3 chars","a":1}', 1),
        (
            "https://api.local/hook?api_key=secret123&mode=fast",
            "https://api.local/hook?api_key=redacted 9 chars&mode=fast",
            1,
        ),
    )
    for raw, expected, expected_count in exact_cases:
        scrubbed, count = redact_memory_text(raw)
        assert scrubbed == expected, f"{raw!r} -> {scrubbed!r}"
        assert count == expected_count
        assert "REAL_SECRET" not in scrubbed
        assert redact_memory_text(scrubbed) == (expected, 0)

    # 2. Crafted double/triple closing-delimiter & comma/semicolon bypasses must NEVER leak
    crafted_cases: tuple[str, ...] = (
        "token=redacted 6 chars))REAL_SECRET",
        "token=redacted 6 chars)]REAL_SECRET",
        "token=redacted 6 chars)}REAL_SECRET",
        'token=redacted 6 chars)"REAL_SECRET',
        "token=redacted 6 chars)'REAL_SECRET",
        "token=redacted 6 chars),REAL_SECRET",
        "token=redacted 6 chars)))REAL_SECRET",
        "token=redacted 6 chars,REAL_SECRET",
        "token=redacted 6 chars;REAL_SECRET",
        "token=redacted 6 chars&REAL_SECRET",
        'token="redacted 6 chars"REAL_SECRET',
        'token="[REDACTED]"REAL_SECRET',
        "Bearer redacted 3 chars))REAL_SECRET",
        "Authorization: Bearer redacted 3 chars))REAL_SECRET",
        "Authorization=Bearer redacted 3 chars))REAL_SECRET",
        "token=[REDACTED]))REAL_SECRET",
        "Bearer [REDACTED]))REAL_SECRET",
        "Bearer [REDACTED],REAL_SECRET",
        "Authorization: Bearer [REDACTED],REAL_SECRET",
        "Authorization: Bearer [REDACTED];REAL_SECRET",
        "Bearer redacted 3 chars,REAL_SECRET",
        "Authorization: Bearer redacted 3 chars,REAL_SECRET",
        'Authorization: Bearer "redacted 3 chars"REAL_SECRET',
    )
    for crafted in crafted_cases:
        try:
            scrubbed, count = redact_memory_text(crafted)
        except MemoryValidationError:
            continue
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {crafted!r}: {scrubbed!r}"
        assert "]," not in scrubbed and "];" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)


@pytest.mark.n1
def test_memory_redaction_r6_unquoted_comma_tails_nested_json_escaped_quotes_and_quoted_kv() -> (
    None
):
    # 1. Comma/semicolon + quote/brace tails on unquoted tokens/placeholders must scrub cleanly
    unquoted_tail_bypasses: tuple[str, ...] = (
        'Bearer redacted 3 chars,"REAL_SECRET"',
        "Bearer redacted 3 chars,'REAL_SECRET'",
        'Bearer redacted 3 chars;"REAL_SECRET"',
        "Bearer redacted 3 chars;'REAL_SECRET'",
        "Bearer redacted 3 chars,}REAL_SECRET",
        'token=redacted 6 chars,"REAL_SECRET"',
        "token=redacted 6 chars,'REAL_SECRET'",
        'token=redacted 6 chars;"REAL_SECRET"',
        "token=redacted 6 chars,}REAL_SECRET",
        'Authorization: Bearer redacted 3 chars,"REAL_SECRET"',
        'Bearer [REDACTED],"REAL_SECRET"',
        'token=[REDACTED],"REAL_SECRET"',
        'Authorization: Bearer [REDACTED],"REAL_SECRET"',
    )
    for raw in unquoted_tail_bypasses:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 2. Nested JSON objects/arrays under sensitive keys + escaped quotes + quoted KV + tail
    exact_r6_cases: tuple[tuple[str, str, int], ...] = (
        (
            '{"credentials": {"note": "REAL_SECRET"}}',
            '{"credentials": {"note": "redacted 11 chars"}}',
            1,
        ),
        (
            '{"credentials": ["REAL_SECRET", "SECOND_SECRET"]}',
            '{"credentials": ["redacted 11 chars", "redacted 13 chars"]}',
            2,
        ),
        (
            '{"token": ["REAL_SECRET", "SECOND_SECRET"]}',
            '{"token": ["redacted 11 chars", "redacted 13 chars"]}',
            2,
        ),
        (
            '{"authorization": {"raw": "REAL_SECRET"}}',
            '{"authorization": {"raw": "redacted 11 chars"}}',
            1,
        ),
        (
            '{"credentials": {"Authorization": "Bearer tok"}}',
            '{"credentials": {"Authorization": "Bearer redacted 3 chars"}}',
            1,
        ),
        (
            '{"token": "abc\\" REAL_SECRET"}',
            '{"token": "redacted 17 chars"}',
            1,
        ),
        (
            '{"Authorization": "Bearer \\"REAL_SECRET\\""}',
            '{"Authorization": "Bearer \\"redacted 11 chars\\""}',
            1,
        ),
        (
            '{"note": "Bearer \\"REAL_SECRET\\""}',
            '{"note": "Bearer \\"redacted 11 chars\\""}',
            1,
        ),
        (
            '{"Authorization": "Bearer \\"[REDACTED]\\""}',
            '{"Authorization": "Bearer \\"redacted 10 chars\\""}',
            1,
        ),
        ('token="REAL_SECRET",SECOND_SECRET', "token=redacted 27 chars", 1),
        ("token='REAL_SECRET';SECOND_SECRET", "token=redacted 27 chars", 1),
        # Re-verify flat JSON, enclosures, and directives remain intact & idempotent
        ('{"auth":"Bearer tok","a":1}', '{"auth":"Bearer redacted 3 chars","a":1}', 1),
        (
            '{"token": "REAL_SECRET", "next": "ok"}',
            '{"token": "redacted 11 chars", "next": "ok"}',
            1,
        ),
        ("((token=abc123))", "((token=redacted 6 chars))", 1),
        ("Bearer tok, next", "Bearer redacted 3 chars, next", 1),
        ("Bearer tok;realm=foo", "Bearer redacted 3 chars;realm=foo", 1),
        (
            "https://api.local/hook?api_key=secret123&mode=fast",
            "https://api.local/hook?api_key=redacted 9 chars&mode=fast",
            1,
        ),
    )
    for raw, expected, expected_count in exact_r6_cases:
        scrubbed, count = redact_memory_text(raw)
        assert scrubbed == expected, f"{raw!r} -> {scrubbed!r}"
        assert count == expected_count
        assert "REAL_SECRET" not in scrubbed
        assert "SECOND_SECRET" not in scrubbed
        assert redact_memory_text(scrubbed) == (expected, 0)

    # Malformed nested JSON under sensitive key must still scrub without leaking
    malformed_nested, malformed_count = redact_memory_text('{"credentials": {"note": "REAL_SECRET"')
    assert "REAL_SECRET" not in malformed_nested
    assert malformed_count == 1
    assert redact_memory_text(malformed_nested) == (malformed_nested, 0)


@pytest.mark.n1
def test_memory_redaction_r7_structural_bypasses_and_caller_paths(tmp_path: Path) -> None:
    # 1. Non-whitespace structured tails attached to tokens/placeholders (Aud-F1)
    aud_f1_cases: tuple[str, ...] = (
        'token=[REDACTED]{"a": "REAL_SECRET"}',
        'token=abc{"a": "REAL_SECRET"}',
        'token=redacted 6 chars{"a": "REAL_SECRET"}',
        'Bearer [REDACTED]{"a": "REAL_SECRET"}',
        'Authorization: Bearer [REDACTED]{"a": "REAL_SECRET"}',
        'Bearer redacted 3 chars{"a": "REAL_SECRET"}',
        'token=[REDACTED]["REAL_SECRET"]',
        'Bearer [REDACTED]["REAL_SECRET"]',
    )
    for raw in aud_f1_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 2. Stray closing quotes + space / comma-key (Cha-F1, Rev-F1) + clean preservation
    stray_quote_cases: tuple[str, ...] = (
        'Bearer redacted 3 chars" REAL_SECRET',
        "Bearer redacted 3 chars' REAL_SECRET",
        'token=redacted 6 chars" REAL_SECRET',
        "token=redacted 6 chars' REAL_SECRET",
        'api_key=redacted 6 chars" REAL_SECRET',
        'Authorization: Bearer redacted 3 chars" REAL_SECRET',
        'Bearer [REDACTED]" REAL_SECRET',
        'token=[REDACTED]" REAL_SECRET',
        'Bearer redacted 3 chars","a":"REAL_SECRET"',
        'Bearer redacted 3 chars;" REAL_SECRET"',
        'token=redacted 6 chars" "REAL_SECRET"',
    )
    for raw in stray_quote_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    for clean_raw in (
        '{"note": "token=redacted 6 chars"}',
        '{"note": "token=redacted 6 chars", "a": 1}',
        '{"note": "Bearer redacted 3 chars", "a": 1}',
    ):
        assert redact_memory_text(clean_raw) == (clean_raw, 0)

    # 3. Multiline malformed/truncated JSON under sensitive keys (Cha-F2, Rev-F2)
    multiline_cases: tuple[str, ...] = (
        '{\n  "token": [\n    "REAL_SECRET",\n    "SECOND_SECRET"\n',
        '{\n  "credentials": {\n    "note": "REAL_SECRET",\n    "raw": "SECOND_SECRET"\n',
        '{\n\t"password": {\n\t\t"p": "REAL_SECRET"\n',
        '{"credentials": {\n  "note": "REAL_SECRET"\n',
        'credentials=[\n  "REAL_SECRET"\n',
    )
    for raw in multiline_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed
        assert "SECOND_SECRET" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 4. Escaped-quote / nested JSON-in-JSON strings (Aud-F2, Cha-F3, Rev-F3a)
    nested_escaped_cases: tuple[str, ...] = (
        json.dumps({"outer": json.dumps({"credentials": {"note": "REAL_SECRET"}})}),
        r'\"credentials\": {\"note\": \"REAL_SECRET\"}',
        '{"note": "{\\"credentials\\": {\\"raw\\": \\"REAL_SECRET\\"}}"}',
        '{"note": "{\\"token\\": [\\"REAL_SECRET\\", \\"SECOND_SECRET\\"]}"}',
        '{"note": "{\\"Authorization\\": \\"Bearer \\\\\\"REAL_SECRET\\\\\\"\\"}"}',
        r'\"token\": [\"REAL_SECRET\", \"SECOND_SECRET\"]',
    )
    for raw in nested_escaped_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert "SECOND_SECRET" not in scrubbed, f"Leaked2 on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 5. JSON-escaped \" (\\\" on the wire) inside Bearer "..." (Aud-F3, Rev-F3b)
    escaped_bearer_cases: tuple[str, ...] = (
        json.dumps({"note": 'Bearer "abc\\" REAL_SECRET"'}),
        r'Authorization: Bearer \"abc\\\" REAL_SECRET\"',
        r'{"payload": "{\"token\": \"abc\\\" REAL_SECRET\"}"}',
    )
    for raw in escaped_bearer_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 6. Valid key={...} / key=[...] normalization (Aud-F4) on pass 1 and pass 2
    aud_f4_exact: tuple[tuple[str, str, int], ...] = (
        ('token={"a": "REAL_SECRET"}', 'token={"a": "redacted 11 chars"}', 1),
        (
            'token=["REAL_SECRET", "SECOND_SECRET"]',
            'token=["redacted 11 chars", "redacted 13 chars"]',
            2,
        ),
        ('token={"a": "REAL_SECRET"}, next=ok', 'token={"a": "redacted 11 chars"}, next=ok', 1),
        ('token={"a": "REAL_SECRET"};next=ok', 'token={"a": "redacted 11 chars"};next=ok', 1),
        (
            'token={"a": "REAL_SECRET"}, "SECOND_SECRET"',
            'token={"a": "redacted 11 chars"}, "SECOND_SECRET"',
            1,
        ),
        (
            'token=["REAL_SECRET"], "SECOND_SECRET"',
            'token=["redacted 11 chars"], "SECOND_SECRET"',
            1,
        ),
    )
    for raw, expected, expected_count in aud_f4_exact:
        scrubbed, count = redact_memory_text(raw)
        assert scrubbed == expected, f"{raw!r} -> {scrubbed!r}"
        assert count == expected_count
        assert "REAL_SECRET" not in scrubbed
        assert redact_memory_text(scrubbed) == (expected, 0)

    no_space_tail, no_space_count = redact_memory_text(
        'token={"a": "REAL_SECRET"},"SECOND_SECRET"'
    )
    assert "REAL_SECRET" not in no_space_tail
    assert "SECOND_SECRET" not in no_space_tail
    assert no_space_count >= 1
    assert redact_memory_text(no_space_tail) == (no_space_tail, 0)

    # 7. Unclosed escaped quotes (Cha-F4) with strict c2 == 0 idempotency
    unclosed_escaped_cases: tuple[str, ...] = (
        r'Bearer \"REAL_SECRET,SECOND_SECRET',
        r"Bearer \'REAL_SECRET,SECOND_SECRET",
        r'token=\"REAL_SECRET,SECOND_SECRET',
        r"token=\'REAL_SECRET,SECOND_SECRET",
    )
    for raw in unclosed_escaped_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed
        assert "SECOND_SECRET" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 8. Real MemoryStore caller integration: SQLite + FTS5 + context injection + export
    store = MemoryStore(tmp_path / "r7_callers.sqlite3")
    ctx = MemoryAccessContext(user_id="alice", actor_role="Operator")

    store_inputs: tuple[str, ...] = (
        'token=[REDACTED]{"a": "REAL_SECRET"}',
        'Bearer redacted 3 chars" REAL_SECRET',
        '{\n  "token": [\n    "REAL_SECRET",\n    "SECOND_SECRET"\n',
        json.dumps({"outer": json.dumps({"credentials": {"note": "REAL_SECRET"}})}),
        json.dumps({"note": 'Bearer "abc\\" REAL_SECRET"'}),
        'token={"a": "REAL_SECRET"}',
        r'Bearer \"REAL_SECRET,SECOND_SECRET',
    )
    stored_contents: list[str] = []
    for idx, payload in enumerate(store_inputs):
        created = store.create_memory(
            scope="user",
            scope_id="alice",
            kind="source_reference",
            title=f"R7 item {idx}",
            content=payload,
        )
        assert "REAL_SECRET" not in created["content"]
        assert "SECOND_SECRET" not in created["content"]
        stored_contents.append(created["content"])

    assert 'token={"a": "redacted 11 chars"}' in stored_contents
    assert store.search_memories(ctx, "REAL_SECRET") == []
    assert store.search_memories(ctx, "SECOND_SECRET") == []

    bundle = store.build_context_injection(
        ctx,
        thread_passages=[
            '{\n  "token": [\n    "REAL_SECRET",\n    "SECOND_SECRET"\n',
            'token={"a": "REAL_SECRET"}',
            json.dumps({"outer": json.dumps({"credentials": {"note": "REAL_SECRET"}})}),
            r'Bearer \"REAL_SECRET,SECOND_SECRET',
        ],
    )
    assert "REAL_SECRET" not in bundle.recall_text
    assert "SECOND_SECRET" not in bundle.recall_text
    assert bundle.passage_count == 4

    exported_json = json.loads(store.export_memories(ctx, fmt="json"))
    exported_contents = [item["content"] for item in exported_json["items"]]
    assert sorted(exported_contents) == sorted(stored_contents)

    export_md = tmp_path / "r7_export.md"
    store.export_to_file(export_md, ctx, fmt="md")
    assert stat.S_IMODE(os.stat(export_md).st_mode) == 0o600
    md_text = export_md.read_text(encoding="utf-8")
    assert "REAL_SECRET" not in md_text
    assert "SECOND_SECRET" not in md_text
    assert 'token={"a": "redacted 11 chars"}' in md_text
    store.close()


@pytest.mark.n1
def test_memory_redaction_r8_scalars_keys_quotes_escaping_and_redos() -> None:
    # 1. Violation 1: _normalize_probe slice preservation + multi-token scrubbing
    probe_kv = _normalize_probe('{"a": 1} token=LEAKED [tag]')
    assert "token=LEAKED" in probe_kv
    assert contains_unredacted_secret_strict(probe_kv) is True
    assert contains_unredacted_secret_strict(_normalize_probe('{"a": 1} Bearer LEAKED [tag]'))
    assert contains_unredacted_secret_strict(
        _normalize_probe('{"a": 1} https://user:LEAKED@host/path [tag]')
    )

    multi_scrub, multi_count = redact_memory_text(
        'token={"a": "REAL_SECRET"} token=SECOND_SECRET'
    )
    assert multi_scrub == 'token={"a": "redacted 11 chars"} token=redacted 13 chars'
    assert multi_count == 2
    assert redact_memory_text(multi_scrub) == (multi_scrub, 0)

    prefixed_multi, prefixed_count = redact_memory_text(
        '{"note": "ok"} token={"a": "REAL_SECRET"} token=SECOND_SECRET'
    )
    assert "REAL_SECRET" not in prefixed_multi
    assert "SECOND_SECRET" not in prefixed_multi
    assert prefixed_count == 2
    assert redact_memory_text(prefixed_multi) == (prefixed_multi, 0)

    # 2. Violation 2: nested Authorization Bearer/Basic inside key={...} / key=[...]
    for raw in (
        'token={"Authorization": "Bearer REAL_SECRET"}',
        'token=[{"Authorization": "Bearer REAL_SECRET"}]',
        'credentials={"Authorization": "Basic REAL_SECRET"}',
        r'\"token\"={\"Authorization\": \"Bearer REAL_SECRET\"}',
    ):
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"{raw!r} -> {scrubbed!r}"
        assert count == 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    clean_nested_auth = 'token={"Authorization": "Bearer redacted 11 chars"}'
    assert redact_memory_text(clean_nested_auth) == (clean_nested_auth, 0)

    # 3. Violation 3 & Challenger Bug 1: JSON-escaped & backslash-escaped quoted KV
    for raw in (
        '{"note": "token=\\"REAL_SECRET\\""}',
        json.dumps({"note": 'token="abc\\" REAL_SECRET"'}),
        json.dumps({"a": json.dumps({"note": 'token="REAL_SECRET"'})}),
        json.dumps({"a": json.dumps({"b": json.dumps({"note": 'token="REAL_SECRET"'})})}),
        r'token=\\\"abc\\\\\\\" REAL_SECRET\\\"',
    ):
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"{raw!r} -> {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    clean_quoted_kv = json.dumps({"note": 'token="redacted 6 chars"'})
    assert redact_memory_text(clean_quoted_kv) == (clean_quoted_kv, 0)

    # 4. Reviewer Finding 1: quoted/escaped Authorization: "Bearer ..." / "Basic ..."
    for raw in (
        json.dumps({"note": 'Authorization: "Bearer REAL_SECRET"'}),
        json.dumps({"note": 'Authorization: "Bearer [REDACTED]"'}),
        r'Authorization: \"Bearer REAL_SECRET\"',
        r'Authorization: \"Basic dXNlcjpwYXNz\"',
        r'Authorization: \"Bearer \nREAL_SECRET\"',
    ):
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"{raw!r} -> {scrubbed!r}"
        assert "dXNlcjpwYXNz" not in scrubbed, f"{raw!r} -> {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 5. Reviewer Finding 2: non-null numeric/boolean JSON scalars under sensitive keys
    scalar_exact_cases: tuple[tuple[str, str, int], ...] = (
        ('{"token": 123456}', '{"token": "redacted 6 chars"}', 1),
        ('{"token": 3.14}', '{"token": "redacted 4 chars"}', 1),
        ('{"token": true}', '{"token": "redacted 4 chars"}', 1),
        ('{"token": false}', '{"token": "redacted 5 chars"}', 1),
        ('token={"pin": 4321}', 'token={"pin": "redacted 4 chars"}', 1),
        ('password=[123456]', 'password=["redacted 6 chars"]', 1),
        (
            '{"credentials": [123456, "REAL_SECRET"]}',
            '{"credentials": ["redacted 6 chars", "redacted 11 chars"]}',
            2,
        ),
        (
            '{"token": {"nested": {"pin": 9876}}}',
            '{"token": {"nested": {"pin": "redacted 4 chars"}}}',
            1,
        ),
        ('{"token": null}', '{"token": null}', 0),
        ('token={"pin": null}', 'token={"pin": null}', 0),
        ('{"a": 1, "b": true, "c": null}', '{"a": 1, "b": true, "c": null}', 0),
    )
    for raw, expected, expected_count in scalar_exact_cases:
        scrubbed, count = redact_memory_text(raw)
        assert (scrubbed, count) == (expected, expected_count), f"{raw!r} -> {scrubbed!r}"
        assert redact_memory_text(scrubbed) == (expected, 0)

    assert _probe_json_container_is_clean({"pin": 4321}) is False
    assert _probe_json_container_is_clean({"flag": True}) is False
    assert _probe_json_container_is_clean({"Bearer LEAK": "[REDACTED]"}) is False
    assert _probe_json_container_is_clean({"Authorization": "Bearer [REDACTED]"}) is True

    # 6. Auditor Violation 4: unconditional JSON object key scrubbing
    key_scrub_cases: tuple[tuple[str, str, int], ...] = (
        ('{"Bearer MY_SECRET": 1}', '{"Bearer redacted 9 chars": "redacted 1 chars"}', 2),
        ('{"Bearer MYVALUE": 1}', '{"Bearer redacted 7 chars": 1}', 1),
        ('{"token=MY_SECRET": 1}', '{"token=redacted 9 chars": "redacted 1 chars"}', 2),
        (
            '{"token=MY_SECRET": "REAL_SECRET"}',
            '{"token=redacted 9 chars": "redacted 11 chars"}',
            2,
        ),
        ('{"api_key": "REAL_SECRET"}', '{"api_key": "redacted 11 chars"}', 1),
        (
            '{"Authorization": "Bearer REAL_SECRET"}',
            '{"Authorization": "Bearer redacted 11 chars"}',
            1,
        ),
    )
    for raw, expected, expected_count in key_scrub_cases:
        scrubbed, count = redact_memory_text(raw)
        assert (scrubbed, count) == (expected, expected_count), f"{raw!r} -> {scrubbed!r}"
        assert redact_memory_text(scrubbed) == (expected, 0)

    # 7. Challenger Bug 4 + Reviewer Finding 3 + outer-quote leak hardening
    quote_bypass_cases: tuple[str, ...] = (
        '"a"token=redacted 6 chars" REAL_SECRET',
        '"a"Bearer redacted 3 chars" REAL_SECRET',
        '" "token=redacted 6 chars" REAL_SECRET',
        'foo"token=redacted 6 chars" REAL_SECRET',
        'foo"Bearer redacted 3 chars" REAL_SECRET',
        'x"token=redacted 6 chars" REAL_SECRET',
        '1"Bearer redacted 3 chars" REAL_SECRET',
        '"a"(token=redacted 6 chars)" REAL_SECRET',
        r'\"a\"token=redacted 6 chars\" REAL_SECRET',
        'Bearer \\"redacted 3 chars\\"" REAL_SECRET',
        'token=\\"redacted 6 chars\\"" REAL_SECRET',
    )
    for raw in quote_bypass_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    for clean_raw in (
        '"token=redacted 6 chars"',
        '["Bearer redacted 3 chars"]',
        'note: "token=redacted 6 chars"',
        'key="Bearer redacted 3 chars"',
        '(("token=redacted 6 chars"))',
        'foo="a" "token=redacted 6 chars"',
    ):
        assert redact_memory_text(clean_raw) == (clean_raw, 0)

    # 8. Reviewer Finding 4: _re_escape_quoted backslash parity + allow_quoted_enclosure
    raw_f4 = r'Authorization: \"Bearer \\\"abc\\\\\\\" REAL_SECRET\\\"\"'
    s_f4, c_f4 = redact_memory_text(raw_f4)
    assert s_f4 == r'Authorization: \"Bearer \\\"redacted 23 chars\\\"\"'
    assert c_f4 == 1
    assert redact_memory_text(s_f4) == (s_f4, 0)

    # 9. Challenger Bug 3: ReDoS / O(N^2) < 100ms timing + parity checks
    redos_cases: tuple[tuple[str, int], ...] = (
        ("a-" * 5000, 0),
        ("-" * 5000, 0),
        ("a." * 5000, 0),
        ("a-" * 5000 + "_token=REAL_SECRET", 1),
        ("a-" * 5000 + " token=REAL_SECRET", 1),
        ('[{"a":1},' * 2000 + "bad]", 0),
        ("[" * 5000 + "]", 0),
        ("[ " * 5000 + "]", 0),
        ("token=[" * 2000 + "]", 1),
    )
    for raw, expected_c in redos_cases:
        t0 = time.perf_counter()
        scrubbed, count = redact_memory_text(raw)
        dt1 = time.perf_counter() - t0
        t1 = time.perf_counter()
        scrubbed2, count2 = redact_memory_text(scrubbed)
        dt2 = time.perf_counter() - t1
        assert count == expected_c
        assert (scrubbed2, count2) == (scrubbed, 0)
        assert "REAL_SECRET" not in scrubbed
        assert dt1 < 0.1, f"Pass 1 too slow ({dt1:.3f}s) on {raw[:24]!r}"
        assert dt2 < 0.1, f"Pass 2 too slow ({dt2:.3f}s) on {raw[:24]!r}"

    # Valid trailing JSON after malformed prefix must still scrub
    trailing_valid, trailing_c = redact_memory_text(
        '[{"a":1},' * 2000 + '{"token":"REAL_SECRET"}]'
    )
    assert "REAL_SECRET" not in trailing_valid
    assert trailing_c == 1
    assert redact_memory_text(trailing_valid) == (trailing_valid, 0)

    # _fast_contains_unredacted_secret_strict parity on space-separated and long-key probes
    for probe_sample in (
        "a-" * 5000 + "_token=REAL_SECRET",
        "token = REAL_SECRET",
        "Bearer REAL_SECRET",
        "https://user:REAL_SECRET@host/path",
    ):
        assert _fast_contains_unredacted_secret_strict(
            probe_sample
        ) == contains_unredacted_secret_strict(probe_sample)


@pytest.mark.n1
def test_memory_redaction_r9_parity_url_redos_escaped_quotes_and_multi_run_timing() -> None:
    # 1. Auditor R8 Defect 1: multi-run non-flaky < 0.1s on large JSON/KV inputs
    multi_run_cases: tuple[tuple[str, int], ...] = (
        ('[{"a":1},' * 2000 + "bad]", 0),
        ('[{"a":1},' * 2000 + "token=REAL_SECRET]", 1),
        ('[{"a":1},' * 2000 + '{"token":"REAL_SECRET"}]', 1),
    )
    for raw, exp_c in multi_run_cases:
        for run_idx in range(5):
            t0 = time.perf_counter()
            scrubbed, count = redact_memory_text(raw)
            dt1 = time.perf_counter() - t0
            t1 = time.perf_counter()
            scrubbed2, count2 = redact_memory_text(scrubbed)
            dt2 = time.perf_counter() - t1
            assert count == exp_c
            assert (scrubbed2, count2) == (scrubbed, 0)
            assert "REAL_SECRET" not in scrubbed
            if exp_c == 0:
                assert scrubbed == raw
            assert dt1 < 0.1, f"Run {run_idx} Pass 1 too slow ({dt1:.3f}s) on {raw[-24:]!r}"
            assert dt2 < 0.1, f"Run {run_idx} Pass 2 too slow ({dt2:.3f}s) on {raw[-24:]!r}"

    # 2. Auditor R8 Defect 2 + Reviewer F1 + Challenger B2: exact O(N) parity
    parity_cases: tuple[tuple[str, bool], ...] = (
        ("A" * 16 + ".a" + "A" * 130 + "Token=REAL_SECRET", True),
        ("A" * 16 + "-a" + "A" * 130 + "Token=REAL_SECRET", True),
        ("-" * 130 + "A" * 60 + "Password=REAL_SECRET", False),
        ("a" * 70 + "-" + "A" * 70 + "Password=REAL_SECRET", False),
        ("a" + "B" * 70 + "-" + "C" * 60 + "Token=123", False),
        ("a" + "B" * 70 + "." + "C" * 60 + "Token=123", False),
        ("a" + "B" * 70 + "-" + "C" * 60 + "Secret=123", False),
        ("a" + "B" * 70 + "." + "C" * 60 + "ApiKey=123", False),
    )
    for sample, expected_secret in parity_cases:
        assert _fast_contains_unredacted_secret_strict(sample) is expected_secret
        assert bool(contains_unredacted_secret_strict(sample)) is expected_secret
        scrubbed, count = redact_memory_text(sample)
        if expected_secret:
            assert count == 1
            assert "REAL_SECRET" not in scrubbed
        else:
            assert (scrubbed, count) == (sample, 0)
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    rng = random.Random(20261126)
    alphabet = list("abAB01_.-:/@= &'\",;[]{}()\\")
    tokens = [
        "token",
        "Token",
        "Bearer",
        "Basic",
        "[REDACTED]",
        "://",
        "@",
        "=",
        "Password",
        "Secret",
        "ApiKey",
        "SecretKey",
        "Credentials",
        "Cookies",
        "https://",
        "a+",
        "---",
        "___",
        "x_api_key",
        "set-cookie",
        " ",
    ]
    for _ in range(500):
        parts = [
            rng.choice(tokens)
            if rng.random() < 0.5
            else "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))
            for _ in range(rng.randint(1, 10))
        ]
        fuzz_s = "".join(parts)
        assert _fast_contains_unredacted_secret_strict(fuzz_s) == bool(
            contains_unredacted_secret_strict(fuzz_s)
        ), f"Parity mismatch on {fuzz_s!r}"

    # 3. Challenger B1: URL ReDoS < 0.1s
    url_redos_cases: tuple[tuple[str, int], ...] = (
        ("https://" + "a+" * 30000, 0),
        ("a+" * 15000 + "://" + "x" * 5000, 0),
        ("a+" * 15000 + "://" + "@", 0),
        ("https://user:REAL_SECRET@" + "a+" * 5000, 1),
    )
    for raw, exp_c in url_redos_cases:
        t0 = time.perf_counter()
        scrubbed, count = redact_memory_text(raw)
        dt1 = time.perf_counter() - t0
        t1 = time.perf_counter()
        scrubbed2, count2 = redact_memory_text(scrubbed)
        dt2 = time.perf_counter() - t1
        assert count == exp_c
        assert (scrubbed2, count2) == (scrubbed, 0)
        assert "REAL_SECRET" not in scrubbed
        assert dt1 < 0.1, f"URL Pass 1 too slow ({dt1:.3f}s)"
        assert dt2 < 0.1, f"URL Pass 2 too slow ({dt2:.3f}s)"

    # 4. Reviewer R8 Finding 2: backslash-escaped quote enclosures (positive + contrast)
    escaped_quote_positive: tuple[tuple[str, str, int], ...] = (
        (r'\"token=redacted 6 chars\"', r'\"token=redacted 6 chars\"', 0),
        (
            json.dumps({"note": r'\"token=redacted 6 chars\"'}),
            json.dumps({"note": r'\"token=redacted 6 chars\"'}),
            0,
        ),
        (r'"\"token=redacted 6 chars\""', r'"\"token=redacted 6 chars\""', 0),
        (r'\"token=REAL_SECRET\"', r'\"token=redacted 11 chars\"', 1),
        (r'\"Bearer REAL_SECRET\"', r'\"Bearer redacted 11 chars\"', 1),
        (r'\"token=\\\"REAL_SECRET\\\"\"', r'\"token=\\\"redacted 11 chars\\\"\"', 1),
        (r'\"token=\\"REAL_SECRET\\"\"', r'\"token=redacted 17 chars\"', 1),
        (
            r'\"token=redacted 6 chars\" REAL_SECRET',
            r'\"token=redacted 6 chars\" REAL_SECRET',
            0,
        ),
        (r"\'token=redacted 6 chars\'", r"\'token=redacted 6 chars\'", 0),
        (r"\'token=REAL_SECRET\'", r"\'token=redacted 11 chars\'", 1),
        (r"\'Bearer REAL_SECRET\'", r"\'Bearer redacted 11 chars\'", 1),
    )
    for raw, expected, exp_c in escaped_quote_positive:
        scrubbed, count = redact_memory_text(raw)
        assert (scrubbed, count) == (expected, exp_c), f"{raw!r} -> {(scrubbed, count)!r}"
        assert redact_memory_text(scrubbed) == (expected, 0)

    escaped_quote_contrast: tuple[str, ...] = (
        'Bearer \\"redacted 3 chars\\"" REAL_SECRET',
        'token=\\"redacted 6 chars\\"" REAL_SECRET',
        r'\"a\"token=redacted 6 chars\" REAL_SECRET',
        'foo"token=redacted 6 chars" REAL_SECRET',
        '"a"token=redacted 6 chars" REAL_SECRET',
        r'\"token=REAL_SECRET\"SECOND_SECRET',
        r'\"token=redacted 6 chars\"REAL_SECRET',
    )
    for raw in escaped_quote_contrast:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed, f"Leaked on {raw!r}: {scrubbed!r}"
        assert "SECOND_SECRET" not in scrubbed, f"Leaked2 on {raw!r}: {scrubbed!r}"
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)


@pytest.mark.n1
def test_memory_redaction_r10_quote_tracker_perf_unicode_auth_json_in_json_and_parens() -> None:
    # 1. Challenger R9 Bug 1: O(N) random-access _QuoteEnclosureTracker (no O(N^2) cursor reset)
    sample = r'"\"inner\" \'single\' \\\"deep\\\" end"'
    tr_rand = _QuoteEnclosureTracker(sample)
    expected_stacks = [
        _QuoteEnclosureTracker(sample).stack_at(pos) for pos in range(len(sample) + 1)
    ]
    for pos in reversed(range(len(sample) + 1)):
        assert tr_rand.stack_at(pos) == expected_stacks[pos]
    for pos in (3, 15, 1, len(sample), 8, 2, 19, 0):
        assert tr_rand.stack_at(pos) == expected_stacks[pos]

    dos_cases: tuple[tuple[str, int], ...] = (
        ('[{"note":"token=1"},' * 1500 + "bad]", 1500),
        (r'\"token=redacted 6 chars\" ' * 1100, 0),
        (r'\"Bearer redacted 6 chars\" ' * 1000, 0),
    )
    for raw, exp_c in dos_cases:
        t0 = time.perf_counter()
        scrubbed, count = redact_memory_text(raw)
        dt1 = time.perf_counter() - t0
        t1 = time.perf_counter()
        scrubbed2, count2 = redact_memory_text(scrubbed)
        dt2 = time.perf_counter() - t1
        assert count == exp_c
        assert (scrubbed2, count2) == (scrubbed, 0)
        assert dt1 < 0.15, f"Bug 1 Pass 1 too slow ({dt1:.3f}s) on {raw[:24]!r}"
        assert dt2 < 0.15, f"Bug 1 Pass 2 too slow ({dt2:.3f}s) on {raw[:24]!r}"

    # 2. Reviewer R9 F1 + Challenger R9 Bug 2: multi-run < 0.1s perf across all 4 payloads
    perf_cases: tuple[tuple[str, int], ...] = (
        ("a=" * 20000, 0),
        ('[{"token":"1"},' * 2000 + "bad]", 2000),
        ("token=1 " * 2000, 2000),
        ('[{"a":1},' * 2000 + '{"token":"REAL_SECRET"}]', 1),
    )
    for raw, exp_c in perf_cases:
        for run_idx in range(3):
            t0 = time.perf_counter()
            scrubbed, count = redact_memory_text(raw)
            dt1 = time.perf_counter() - t0
            t1 = time.perf_counter()
            scrubbed2, count2 = redact_memory_text(scrubbed)
            dt2 = time.perf_counter() - t1
            assert count == exp_c
            assert (scrubbed2, count2) == (scrubbed, 0)
            assert "REAL_SECRET" not in scrubbed
            assert dt1 < 0.1, f"R10 perf Run {run_idx} Pass 1 slow ({dt1:.3f}s) on {raw[:20]!r}"
            assert dt2 < 0.1, f"R10 perf Run {run_idx} Pass 2 slow ({dt2:.3f}s) on {raw[:20]!r}"

    # 3. Challenger R9 Bug 3: Unicode case-folding (ſ U+017F, K U+212A, İ U+0130, ı U+0131)
    unicode_secret_cases: tuple[tuple[str, bool], ...] = (
        ("setCookie\u017fsession_token=BASICsecret", True),
        ("a\u017fb_token=REAL_SECRET", True),
        ("a\u212ab_token=REAL_SECRET", True),
        ("x-\u017f_token=REAL_SECRET", True),
        ("\u017fecret=REAL_SECRET", True),
        ("api_\u212aey=REAL_SECRET", True),
        ("cookie\u017f=REAL_SECRET", True),
        ("pa\u017fswd=REAL_SECRET", True),
        ("ap\u0131_key=REAL_SECRET", True),
        ("ap\u0131key=REAL_SECRET", True),
        ("ap\u0130key=REAL_SECRET", True),
        ("ba\u017fic REAL_SECRET", True),
        ("\u017fetCookie=REAL_SECRET", True),
        ("ACCESSTOKEN=REAL_SECRET", True),
        ("aB\u0131Token=REAL_SECRET", False),
        ("aB\u212aToken=REAL_SECRET", False),
    )
    for sample_u, expected_secret in unicode_secret_cases:
        assert _fast_contains_unredacted_secret_strict(sample_u) is expected_secret
        assert bool(contains_unredacted_secret_strict(sample_u)) is expected_secret
        scrubbed, count = redact_memory_text(sample_u)
        if expected_secret:
            assert count >= 1
            assert "REAL_SECRET" not in scrubbed
            assert "BASICsecret" not in scrubbed
        else:
            assert (scrubbed, count) == (sample_u, 0)
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 4. Challenger R9 Bug 4: quoted Authorization: Bearer, nested JSON-in-JSON, quoted (token=...)
    bug4_exact_cases: tuple[tuple[str, str, int], ...] = (
        (
            r'\"Authorization: Bearer REAL_SECRET\"',
            r'\"Authorization: Bearer redacted 11 chars\"',
            1,
        ),
        (r'"Authorization: Bearer REAL_SECRET"', r'"Authorization: Bearer redacted 11 chars"', 1),
        (
            r'"Authorization: Bearer redacted 11 chars"',
            r'"Authorization: Bearer redacted 11 chars"',
            0,
        ),
        (
            r'\"Authorization: Bearer redacted 11 chars\"',
            r'\"Authorization: Bearer redacted 11 chars\"',
            0,
        ),
        (
            r"'Authorization: Bearer redacted 11 chars'",
            r"'Authorization: Bearer redacted 11 chars'",
            0,
        ),
        (
            r'\"(Authorization: Bearer REAL_SECRET)\"',
            r'\"(Authorization: Bearer redacted 11 chars)\"',
            1,
        ),
        ('{"note": "{\\"Bearer x\\": 1}"}', '{"note": "{\\"Bearer redacted 1 chars\\": 1}"}', 1),
        ('{"note": "{\\"Basic x\\": 1}"}', '{"note": "{\\"Basic redacted 1 chars\\": 1}"}', 1),
        ('{"note": "{\\"token=x\\": 1}"}', '{"note": "{\\"token=redacted 1 chars\\": 1}"}', 1),
        ('{"{\\"Bearer x\\": 1}": 1}', '{"{\\"Bearer redacted 1 chars\\": 1}": 1}', 1),
        ('{"{\\"Basic x\\": 1}": 1}', '{"{\\"Basic redacted 1 chars\\": 1}": 1}', 1),
        ('{"{\\"token=x\\": 1}": 1}', '{"{\\"token=redacted 1 chars\\": 1}": 1}', 1),
        (
            '{"note": "{\\"Bearer x\\": \\"REAL_SECRET\\"}"}',
            '{"note": "{\\"Bearer redacted 1 chars\\": \\"REAL_SECRET\\"}"}',
            1,
        ),
        (r'\"(token=REAL_SECRET)\"', r'\"(token=redacted 11 chars)\"', 1),
        (r'\"(token=redacted 6 chars)\"', r'\"(token=redacted 6 chars)\"', 0),
        (r'"(token=redacted 6 chars)"', r'"(token=redacted 6 chars)"', 0),
        (r'"(token=REAL_SECRET)"', r'"(token=redacted 11 chars)"', 1),
    )
    for raw, expected, exp_c in bug4_exact_cases:
        scrubbed, count = redact_memory_text(raw)
        assert (scrubbed, count) == (expected, exp_c), f"{raw!r} -> {(scrubbed, count)!r}"
        assert redact_memory_text(scrubbed) == (expected, 0)

    for contrast_raw in (
        r'\"(token=redacted 6 chars)\"REAL_SECRET',
        '"(token=redacted 6 chars)"REAL_SECRET',
        '"a"(token=redacted 6 chars)" REAL_SECRET',
    ):
        scrubbed, count = redact_memory_text(contrast_raw)
        assert "REAL_SECRET" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)


@pytest.mark.n1
def test_memory_redaction_r11_json_in_json_values_arrays_and_skip_step0() -> None:
    # 1. Reviewer R10 F1 + Challenger R10 Bug 1: nested JSON-in-JSON string values,
    #    array items, and quoted key=value inside JSON strings
    bug1_cases: tuple[tuple[str, int, tuple[str, ...]], ...] = (
        ('{"note": "{\\"a\\": \\"token=REAL_SECRET\\"}"}', 1, ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": \\"token=redacted 11 chars\\"}"}', 0, ()),
        ('{"note": "{\\"a\\": [\\"token=REAL_SECRET\\"]}"}', 1, ("REAL_SECRET",)),
        ('{"note": "[\\"token=REAL_SECRET\\"]"}', 1, ("REAL_SECRET",)),
        ('{"note": "{\\"Bearer x\\": \\"token=REAL_SECRET\\"}"}', 2, ("REAL_SECRET",)),
        ('{"note": "{\\"token=x\\": \\"token=REAL_SECRET\\"}"}', 2, ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": {\\"b\\": \\"token=REAL_SECRET\\"}}"}', 1, ("REAL_SECRET",)),
        (
            '{"outer": "{\\"mid\\": \\"{\\\\\\"a\\\\\\": \\\\\\"token=REAL_SECRET\\\\\\"}\\"}"}',
            1,
            ("REAL_SECRET",),
        ),
        (
            '{"outer": "{\\"mid\\": \\"{\\\\\\"a\\\\\\": \\\\\\"Bearer REAL_SECRET\\\\\\"}\\"}"}',
            1,
            ("REAL_SECRET",),
        ),
        ('{"note": "{\\"a\\": \\"token=1\\"}"}', 1, ("=1",)),
        ('{"note": "{\\"a\\": \\"secret=1\\"}"}', 1, ("=1",)),
        ('{"note": "{\\"a\\": \\"api_key=1\\"}"}', 1, ("=1",)),
        ('{"note": "see \\"token=abc\\" ok"}', 1, ("abc",)),
        ('{"note": "prefix \\"token=REAL_SECRET\\""}', 1, ("REAL_SECRET",)),
        ('{"note": "(\\"token=REAL_SECRET\\")"}', 1, ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": \\"(token=REAL_SECRET)\\"}"}', 1, ("REAL_SECRET",)),
    )
    for raw, exp_count, forbidden in bug1_cases:
        scrubbed, count = redact_memory_text(raw)
        assert count == exp_count, f"{raw!r} -> {(scrubbed, count)!r}"
        for bad in forbidden:
            assert bad not in scrubbed, f"Leaked {bad!r} on {raw!r}: {scrubbed!r}"
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # Contrast cases: multi-secret, stray quote inside JSON string, unredacted tail
    multi_s, multi_c = redact_memory_text(
        '{"note": "{\\"a\\": \\"token=REAL_SECRET token=LEAKED\\"}"}'
    )
    assert "REAL_SECRET" not in multi_s
    assert "LEAKED" not in multi_s
    assert multi_c == 2
    assert redact_memory_text(multi_s) == (multi_s, 0)

    stray_s, stray_c = redact_memory_text('{"note": "see token=redacted 3 chars\\" REAL_SECRET"}')
    assert "REAL_SECRET" not in stray_s
    assert stray_c >= 1
    assert redact_memory_text(stray_s) == (stray_s, 0)

    tail_raw = '{"note": "{\\"a\\": \\"token=[REDACTED]\\"}"} token=LEAKED'
    assert _fast_contains_unredacted_secret_strict(_normalize_probe(tail_raw)) is True
    tail_s, tail_c = redact_memory_text(tail_raw)
    assert "LEAKED" not in tail_s
    assert tail_c >= 1
    assert redact_memory_text(tail_s) == (tail_s, 0)

    # 2. Challenger R10 Bug 2: _may_normalize_leaf / _skip_step0 on pre-norm placeholders
    bug2_cases: tuple[str, ...] = (
        '{"note":"(token=REAL_SECRET)"}bad',
        '{"note":"(token=REAL_SECRET)"}{"a":1}',
        '{"note":"(token=REAL_SECRET)"},{"a":"token=redacted 1 chars"} '
        r'\"Authorization: Bearer REAL_SECRET\"',
        '{"note":"[token=REAL_SECRET]"}bad',
        '{"note":"{token=REAL_SECRET}"}bad',
        '{"note":"(Bearer REAL_SECRET)"}bad',
    )
    for raw in bug2_cases:
        scrubbed, count = redact_memory_text(raw)
        assert "REAL_SECRET" not in scrubbed
        assert count >= 1
        assert redact_memory_text(scrubbed) == (scrubbed, 0)

    # 3. 1,000-case differential fuzz: redact_memory_text vs _normalize_probe(_skip_step0=False)
    rng = random.Random(2026112611)
    leaf_vals = [
        "token=REAL_SECRET",
        "token=redacted 11 chars",
        "(token=REAL_SECRET)",
        "(token=redacted 11 chars)",
        "[token=REAL_SECRET]",
        "{token=REAL_SECRET}",
        'see "token=abc" ok',
        'prefix "token=REAL_SECRET"',
        '("token=REAL_SECRET")',
        "Bearer REAL_SECRET",
        "Bearer redacted 11 chars",
        "(Bearer REAL_SECRET)",
        "sk-1234567890abcdef",
        "clean text",
    ]
    for _ in range(1000):
        inner: dict[str, str] | list[str]
        if rng.random() < 0.6:
            inner = {rng.choice(["a", "Bearer x", "token=x", "note"]): rng.choice(leaf_vals)}
        else:
            inner = [rng.choice(leaf_vals) for _ in range(rng.randint(1, 3))]
        outer = {rng.choice(["note", "data"]): json.dumps(inner)}
        if rng.random() < 0.3:
            outer_3 = {"outer": json.dumps(outer)}
            sample_s = json.dumps(outer_3) + rng.choice(["", "bad", " token=LEAKED"])
        else:
            sample_s = json.dumps(outer) + rng.choice(
                ["", "bad", '{"a":1}', " token=REAL_SECRET", r' \"Bearer REAL_SECRET\"']
            )
        scrubbed_core, _ = _redact_core(sample_s)
        full_probe = _normalize_probe(scrubbed_core, _skip_step0=False)
        full_err = _fast_contains_unredacted_secret_strict(full_probe)
        try:
            out_s, _ = redact_memory_text(sample_s)
            fast_err = False
            assert "REAL_SECRET" not in out_s and "LEAKED" not in out_s
            assert redact_memory_text(out_s) == (out_s, 0)
        except MemoryValidationError:
            fast_err = True
        assert full_err == fast_err, f"Differential mismatch on {sample_s!r}"
