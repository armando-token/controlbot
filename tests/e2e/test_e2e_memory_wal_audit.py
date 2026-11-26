"""Opaque-box E2E tests for M2: Memory FTS5 API, 8-thread WAL concurrency & AuditLog chain."""

from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.e2e._helpers import IsolatedServer

pytestmark = pytest.mark.e2e


def _copy_workspace_db(src_db: Path, dst_db: Path) -> Path:
    """Copy a stopped workspace SQLite DB, sidecars, and vault key to `dst_db`."""
    dst_db.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_db, dst_db)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{src_db}{suffix}")
        if sidecar.exists():
            shutil.copy2(sidecar, Path(f"{dst_db}{suffix}"))
    src_key = src_db.with_name(f".{src_db.stem}.vault.key")
    dst_key = dst_db.with_name(f".{dst_db.stem}.vault.key")
    if src_key.exists():
        shutil.copy2(src_key, dst_key)
        dst_key.chmod(0o600)
    return dst_db


def _seed_audit_mutations(server: IsolatedServer) -> None:
    """Execute real API mutations that append chained rows to workspace_audit_log."""
    with server.client() as client:
        r_set = client.patch("/api/v1/settings", json={"display_name": "E2E Auditor"})
        assert r_set.status_code == 200, r_set.text

        r_apr = client.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Audit chain seed approval",
                "arguments": {"cmd": "uptime"},
            },
        )
        assert r_apr.status_code == 201, r_apr.text
        apr_id = r_apr.json()["id"]

        r_res = client.post(
            f"/api/v1/approvals/{apr_id}/resolve",
            headers={"Idempotency-Key": f"idem-seed-{apr_id}"},
            json={"decision": "allow_once"},
        )
        assert r_res.status_code == 200, r_res.text


# ---------------------------------------------------------------------------
# Feature #8 — Compartmentalized SQLite FTS5 Memory (/api/v1/memory/*) Tier 1
# ---------------------------------------------------------------------------


def test_e2e_memory_post_all_scopes_and_project_alias(server: IsolatedServer) -> None:
    with server.client() as client:
        cases: list[tuple[str, str, dict[str, str], str]] = [
            ("user", "alice", {"X-User-Id": "alice"}, "user"),
            ("agent_role", "safety_bot", {"X-Agent-Role": "safety_bot"}, "agent_role"),
            ("thread", "thr_bot_chief", {"X-Thread-Id": "thr_bot_chief"}, "thread"),
            ("project_area", "turbine_a", {"X-Project-Area": "turbine_a"}, "project_area"),
            ("project", "boiler_b", {"X-Project-Area": "boiler_b"}, "project_area"),
            ("org_approved", "plant_global", {"X-Actor-Role": "Manager"}, "org_approved"),
        ]
        created_ids: list[str] = []
        for raw_scope, scope_id, headers, expected_scope in cases:
            resp = client.post(
                "/api/v1/memory",
                headers=headers,
                json={
                    "scope": raw_scope,
                    "scope_id": scope_id,
                    "kind": "source_reference",
                    "title": f"Ref for {raw_scope}",
                    "content": f"Verified doc for {raw_scope}:{scope_id}",
                },
            )
            assert resp.status_code == 201, resp.text
            body = resp.json()
            assert body["id"].startswith("mem_")
            assert body["scope"] == expected_scope
            assert body["scope_id"] == scope_id
            assert body["kind"] == "source_reference"
            assert body["revision"] == 1
            assert body["created_at"]
            assert body["updated_at"]
            created_ids.append(str(body["id"]))

        assert len(set(created_ids)) == len(cases)


def test_e2e_memory_post_all_kinds(server: IsolatedServer) -> None:
    with server.client() as client:
        r_pref = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "alice"},
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "preference",
                "title": "Table format",
                "content": "Prefer SI units in engineering tables.",
            },
        )
        assert r_pref.status_code == 201, r_pref.text
        assert r_pref.json()["kind"] == "preference"

        r_proc = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "LOTO Valve Isolation",
                "content": "Verify zero energy state before maintenance.",
                "provenance": "manager",
            },
        )
        assert r_proc.status_code == 201, r_proc.text
        assert r_proc.json()["kind"] == "approved_procedure"

        r_obs = client.post(
            "/api/v1/memory",
            headers={"X-Project-Area": "compressor"},
            json={
                "scope": "project_area",
                "scope_id": "compressor",
                "kind": "dated_observation",
                "title": "Vibration baseline",
                "content": "Bearing 2B measured 1.8 mm/s RMS.",
                "observed_at": "2026-11-26T08:00:00Z",
                "valid_until": "2099-01-01T00:00:00Z",
            },
        )
        assert r_obs.status_code == 201, r_obs.text
        obs_body = r_obs.json()
        assert obs_body["kind"] == "dated_observation"
        assert obs_body["observed_at"] == "2026-11-26T08:00:00Z"
        assert obs_body["valid_until"] == "2099-01-01T00:00:00Z"

        r_src = client.post(
            "/api/v1/memory",
            headers={"X-Thread-Id": "thr_1"},
            json={
                "scope": "thread",
                "scope_id": "thr_1",
                "kind": "source_reference",
                "title": "Manual Ch4",
                "content": "OEM manual section 4.2 specifies 45 Nm torque.",
            },
        )
        assert r_src.status_code == 201, r_src.text
        assert r_src.json()["kind"] == "source_reference"


def test_e2e_memory_get_filters_scope_scope_id_kind_q_and_include_expired(
    server: IsolatedServer,
) -> None:
    headers = {
        "X-User-Id": "alice",
        "X-Project-Area": "pump_bay",
        "X-Actor-Role": "Manager",
    }
    with server.client() as client:
        r1 = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "preference",
                "title": "Pump pref",
                "content": "Use metric pressure kPa for alpha_pump.",
            },
        )
        r2 = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "project_area",
                "scope_id": "pump_bay",
                "kind": "dated_observation",
                "title": "Active pump reading",
                "content": "alpha_pump suction steady at 320 kPa.",
                "observed_at": "2026-11-26T08:00:00Z",
                "valid_until": "2099-12-31T00:00:00Z",
            },
        )
        r3 = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "project_area",
                "scope_id": "pump_bay",
                "kind": "dated_observation",
                "title": "Old pump reading",
                "content": "alpha_pump legacy reading 290 kPa.",
                "observed_at": "2020-01-01T00:00:00Z",
                "valid_until": "2020-02-01T00:00:00Z",
            },
        )
        for r in (r1, r2, r3):
            assert r.status_code == 201, r.text
        id_pref = r1.json()["id"]
        id_active = r2.json()["id"]
        id_expired = r3.json()["id"]

        by_scope = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"scope": "user", "scope_id": "alice"},
        )
        assert by_scope.status_code == 200
        assert [it["id"] for it in by_scope.json()["items"]] == [id_pref]

        by_kind = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"scope": "project_area", "scope_id": "pump_bay", "kind": "dated_observation"},
        )
        assert by_kind.status_code == 200
        assert [it["id"] for it in by_kind.json()["items"]] == [id_active]

        by_q = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "alpha_pump"},
        )
        assert by_q.status_code == 200
        q_ids = {it["id"] for it in by_q.json()["items"]}
        assert q_ids == {id_pref, id_active}

        with_exp = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "alpha_pump", "include_expired": "true"},
        )
        assert with_exp.status_code == 200
        exp_ids = {it["id"] for it in with_exp.json()["items"]}
        assert exp_ids == {id_pref, id_active, id_expired}


def test_e2e_memory_patch_updates_fields_and_increments_revision(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        create_resp = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Initial chiller check",
                "content": "Chiller outlet temp 7.2C legacy_keyword",
                "observed_at": "2026-11-26T08:00:00Z",
                "valid_until": "2030-01-01T00:00:00Z",
            },
        )
        assert create_resp.status_code == 201, create_resp.text
        item = create_resp.json()
        assert item["revision"] == 1
        item_id = item["id"]

        patch_resp = client.patch(
            f"/api/v1/memory/{item_id}",
            headers=headers,
            json={
                "revision": 1,
                "title": "Updated chiller check",
                "content": "Chiller outlet temp 6.8C refreshed_keyword",
                "valid_until": "2040-06-01T00:00:00Z",
            },
        )
        assert patch_resp.status_code == 200, patch_resp.text
        updated = patch_resp.json()
        assert updated["revision"] == 2
        assert updated["title"] == "Updated chiller check"
        assert updated["content"] == "Chiller outlet temp 6.8C refreshed_keyword"
        assert updated["valid_until"] == "2040-06-01T00:00:00Z"

        old_search = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "legacy_keyword"},
        )
        assert old_search.status_code == 200
        assert old_search.json()["items"] == []

        new_search = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "refreshed_keyword"},
        )
        assert new_search.status_code == 200
        assert [it["id"] for it in new_search.json()["items"]] == [item_id]


def test_e2e_memory_delete_purges_table_and_fts_docsize(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="mem_del")
    headers = {"X-User-Id": "alice"}
    with srv.client() as client:
        create_resp = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": "Ephemeral FTS purge check",
                "content": "Unique token purge_target_9911 for FTS cleanup.",
            },
        )
        assert create_resp.status_code == 201, create_resp.text
        item_id = str(create_resp.json()["id"])

        del_resp = client.delete(f"/api/v1/memory/{item_id}", headers=headers)
        assert del_resp.status_code == 200, del_resp.text
        assert del_resp.json() == {"deleted": True, "id": item_id}

        get_resp = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "purge_target_9911"},
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["items"] == []

        del_again = client.delete(f"/api/v1/memory/{item_id}", headers=headers)
        assert del_again.status_code == 404

    srv.stop()
    conn = sqlite3.connect(srv.workspace_db_path)
    try:
        row_item = conn.execute(
            "SELECT COUNT(*) FROM memory_items WHERE id = ?", (item_id,)
        ).fetchone()
        assert row_item is not None and int(row_item[0]) == 0

        docsize_count = conn.execute("SELECT COUNT(*) FROM memory_fts_docsize").fetchone()
        assert docsize_count is not None and int(docsize_count[0]) == 0

        fts_hits = conn.execute(
            "SELECT COUNT(*) FROM memory_fts WHERE memory_fts MATCH ?", ('"purge_target_9911"',)
        ).fetchone()
        assert fts_hits is not None and int(fts_hits[0]) == 0
    finally:
        conn.close()


def test_e2e_memory_export_json_and_markdown(server: IsolatedServer) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        r_create = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "preference",
                "title": "Exportable preference",
                "content": "Always include pressure units in bar.",
            },
        )
        assert r_create.status_code == 201, r_create.text
        item_id = r_create.json()["id"]

        exp_json = client.get(
            "/api/v1/memory/export",
            headers=headers,
            params={"format": "json", "scope": "user", "scope_id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        items = exp_json.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == item_id
        assert items[0]["title"] == "Exportable preference"

        exp_md = client.get(
            "/api/v1/memory/export",
            headers=headers,
            params={"format": "md", "scope": "user", "scope_id": "alice"},
        )
        assert exp_md.status_code == 200, exp_md.text
        assert "text/markdown" in exp_md.headers["content-type"]
        assert 'filename="memory_export.md"' in exp_md.headers.get("content-disposition", "")
        assert "# ControlBot Memory Export" in exp_md.text
        assert f"## Exportable preference (`{item_id}`)" in exp_md.text
        assert "Always include pressure units in bar." in exp_md.text


def test_e2e_memory_ttl_expiration_excludes_by_default_and_includes_on_flag(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        r_expired = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Expired sensor reading",
                "content": "Sensor ttl_probe_token read 41.0 C in 2020.",
                "observed_at": "2020-01-01T00:00:00Z",
                "valid_until": "2020-01-02T00:00:00Z",
            },
        )
        assert r_expired.status_code == 201, r_expired.text
        expired_id = r_expired.json()["id"]

        r_valid = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Current sensor reading",
                "content": "Sensor ttl_probe_token read 42.5 C currently.",
                "observed_at": "2026-11-26T00:00:00Z",
                "valid_until": "2099-01-01T00:00:00Z",
            },
        )
        assert r_valid.status_code == 201, r_valid.text
        valid_id = r_valid.json()["id"]

        default_get = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "ttl_probe_token"},
        )
        assert default_get.status_code == 200, default_get.text
        assert [it["id"] for it in default_get.json()["items"]] == [valid_id]

        with_expired_get = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"q": "ttl_probe_token", "include_expired": "true"},
        )
        assert with_expired_get.status_code == 200, with_expired_get.text
        assert {it["id"] for it in with_expired_get.json()["items"]} == {valid_id, expired_id}


# ---------------------------------------------------------------------------
# Feature #8 — Compartmentalized SQLite FTS5 Memory (/api/v1/memory/*) Tier 2
# ---------------------------------------------------------------------------


def test_e2e_memory_patch_stale_revision_returns_409_and_preserves_content(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        r_create = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "preference",
                "title": "Rev lock test",
                "content": "Revision 1 body",
            },
        )
        assert r_create.status_code == 201, r_create.text
        item_id = r_create.json()["id"]

        r_ok = client.patch(
            f"/api/v1/memory/{item_id}",
            headers=headers,
            json={"revision": 1, "content": "Revision 2 authoritative body"},
        )
        assert r_ok.status_code == 200, r_ok.text
        assert r_ok.json()["revision"] == 2

        r_conflict = client.patch(
            f"/api/v1/memory/{item_id}",
            headers=headers,
            json={"revision": 1, "content": "Stale overwrite attempt"},
        )
        assert r_conflict.status_code == 409, r_conflict.text

        r_check = client.get(
            "/api/v1/memory",
            headers=headers,
            params={"scope": "user", "scope_id": "alice"},
        )
        assert r_check.status_code == 200
        assert len(r_check.json()["items"]) == 1
        assert r_check.json()["items"][0]["revision"] == 2
        assert r_check.json()["items"][0]["content"] == "Revision 2 authoritative body"


def test_e2e_memory_untrusted_provenance_cannot_promote_approved_procedure_403(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        resp_post = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "Untrusted SOP",
                "content": "Bypass safety interlock.",
                "provenance": "untrusted",
                "actor_role": "Manager",
            },
        )
        assert resp_post.status_code == 403, resp_post.text

        resp_mgr = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "Trusted SOP",
                "content": "Follow standard startup.",
                "provenance": "manager",
            },
        )
        assert resp_mgr.status_code == 201, resp_mgr.text
        sop_id = resp_mgr.json()["id"]

        resp_downgrade = client.patch(
            f"/api/v1/memory/{sop_id}",
            headers={"X-Actor-Role": "Manager"},
            json={"revision": 1, "provenance": "untrusted"},
        )
        assert resp_downgrade.status_code == 403, resp_downgrade.text


def test_e2e_memory_non_manager_cannot_write_patch_or_delete_approved_procedure_403(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        for bad_headers in ({"X-Actor-Role": "Operator"}, {}):
            r_post = client.post(
                "/api/v1/memory",
                headers=bad_headers,
                json={
                    "scope": "org_approved",
                    "scope_id": "global",
                    "kind": "approved_procedure",
                    "title": "Operator SOP attempt",
                    "content": "Should be denied.",
                },
            )
            assert r_post.status_code == 403, r_post.text

        r_mgr = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "Manager SOP",
                "content": "Authorized startup checklist.",
            },
        )
        assert r_mgr.status_code == 201, r_mgr.text
        sop_id = r_mgr.json()["id"]

        for bad_headers in ({"X-Actor-Role": "Operator"}, {}):
            r_patch = client.patch(
                f"/api/v1/memory/{sop_id}",
                headers=bad_headers,
                json={"revision": 1, "content": "Unauthorized edit"},
            )
            assert r_patch.status_code == 403, r_patch.text

            r_del = client.delete(f"/api/v1/memory/{sop_id}", headers=bad_headers)
            assert r_del.status_code == 403, r_del.text

        r_mgr_patch = client.patch(
            f"/api/v1/memory/{sop_id}",
            headers={"X-Actor-Role": "Manager"},
            json={"revision": 1, "content": "Authorized revision 2."},
        )
        assert r_mgr_patch.status_code == 200, r_mgr_patch.text

        r_mgr_del = client.delete(
            f"/api/v1/memory/{sop_id}",
            headers={"X-Actor-Role": "Manager"},
        )
        assert r_mgr_del.status_code == 200, r_mgr_del.text


def test_e2e_memory_secret_redaction_in_post_get_and_exports(
    server: IsolatedServer,
) -> None:
    sk_secret = "sk-live-secret-token-12345678"
    bearer_tok = "tok-secret-987654321"
    kv_secret = "SuperSecret99!"
    raw_content = (
        f"API key {sk_secret} and header Bearer {bearer_tok} with password={kv_secret} in note."
    )
    headers = {"X-User-Id": "alice"}

    with server.client() as client:
        r_post = client.post(
            "/api/v1/memory",
            headers=headers,
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": f"Secret ref {sk_secret}",
                "content": raw_content,
            },
        )
        assert r_post.status_code == 201, r_post.text
        created = r_post.json()

        r_get = client.get("/api/v1/memory", headers=headers)
        assert r_get.status_code == 200, r_get.text

        r_exp_json = client.get(
            "/api/v1/memory/export",
            headers=headers,
            params={"format": "json"},
        )
        assert r_exp_json.status_code == 200, r_exp_json.text

        r_exp_md = client.get(
            "/api/v1/memory/export",
            headers=headers,
            params={"format": "md"},
        )
        assert r_exp_md.status_code == 200, r_exp_md.text

    expected_sk = f"redacted {len(sk_secret)} chars"
    expected_bearer = f"Bearer redacted {len(bearer_tok)} chars"
    expected_kv = f"password=redacted {len(kv_secret)} chars"

    payloads: list[str] = [
        json.dumps(created),
        json.dumps(r_get.json()),
        json.dumps(r_exp_json.json()),
        r_exp_md.text,
    ]
    for blob in payloads:
        for raw_secret in (sk_secret, bearer_tok, kv_secret):
            assert raw_secret not in blob
        assert expected_sk in blob
        assert expected_bearer in blob
        assert expected_kv in blob


def test_e2e_memory_fts5_punctuation_tokenchars_and_operator_probes(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        fixtures = [
            ("Work order WO-2026500", "Inspect valve on WO-2026500 before shift."),
            ("Tag TT-402B", "Temperature transmitter TT-402B calibrated."),
            ("Fitting 1/4", "Use 1/4 inch stainless tube fitting."),
            ("Pump pump_alpha_01", "Check seal on pump_alpha_01."),
        ]
        ids_by_title: dict[str, str] = {}
        for title, content in fixtures:
            r = client.post(
                "/api/v1/memory",
                headers=headers,
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": title,
                    "content": content,
                },
            )
            assert r.status_code == 201, r.text
            ids_by_title[title] = str(r.json()["id"])

        r_wo = client.get("/api/v1/memory", headers=headers, params={"q": "WO-2026500."})
        assert r_wo.status_code == 200, r_wo.text
        assert [it["id"] for it in r_wo.json()["items"]] == [
            ids_by_title["Work order WO-2026500"]
        ]

        r_tt = client.get("/api/v1/memory", headers=headers, params={"q": "TT-402B"})
        assert r_tt.status_code == 200, r_tt.text
        assert [it["id"] for it in r_tt.json()["items"]] == [ids_by_title["Tag TT-402B"]]

        r_frac = client.get("/api/v1/memory", headers=headers, params={"q": "1/4"})
        assert r_frac.status_code == 200, r_frac.text
        assert [it["id"] for it in r_frac.json()["items"]] == [ids_by_title["Fitting 1/4"]]

        r_under = client.get("/api/v1/memory", headers=headers, params={"q": "pump_alpha_01"})
        assert r_under.status_code == 200, r_under.text
        assert [it["id"] for it in r_under.json()["items"]] == [
            ids_by_title["Pump pump_alpha_01"]
        ]

        for probe in ("NOT OR AND", "-WO-2026500", "WO-2026500*", "...", 'title:"WO'):
            r_probe = client.get("/api/v1/memory", headers=headers, params={"q": probe})
            assert r_probe.status_code == 200, f"Probe {probe!r} failed: {r_probe.text}"
            assert isinstance(r_probe.json()["items"], list)


def test_e2e_memory_acl_isolation_agent_role_user_and_thread(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        r_bot_b = client.post(
            "/api/v1/memory",
            headers={"X-Agent-Role": "bot_b"},
            json={
                "scope": "agent_role",
                "scope_id": "bot_b",
                "kind": "source_reference",
                "title": "Bot B private",
                "content": "Confidential bot_b secret note.",
            },
        )
        assert r_bot_b.status_code == 201, r_bot_b.text
        bot_b_id = r_bot_b.json()["id"]

        r_bob = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "bob"},
            json={
                "scope": "user",
                "scope_id": "bob",
                "kind": "preference",
                "title": "Bob private",
                "content": "Bob personal preference.",
            },
        )
        assert r_bob.status_code == 201, r_bob.text
        bob_id = r_bob.json()["id"]

        r_thr_b = client.post(
            "/api/v1/memory",
            headers={"X-Thread-Id": "thr_b"},
            json={
                "scope": "thread",
                "scope_id": "thr_b",
                "kind": "source_reference",
                "title": "Thread B private",
                "content": "Thread thr_b exclusive context.",
            },
        )
        assert r_thr_b.status_code == 201, r_thr_b.text
        thr_b_id = r_thr_b.json()["id"]

        r_area_b = client.post(
            "/api/v1/memory",
            headers={"X-Project-Area": "area_b"},
            json={
                "scope": "project_area",
                "scope_id": "area_b",
                "kind": "source_reference",
                "title": "Area B private",
                "content": "Project area area_b exclusive blueprint.",
            },
        )
        assert r_area_b.status_code == 201, r_area_b.text
        area_b_id = r_area_b.json()["id"]

        isolation_probes: list[tuple[dict[str, str], dict[str, str], str]] = [
            ({"X-Agent-Role": "bot_a"}, {"scope": "agent_role", "scope_id": "bot_b"}, bot_b_id),
            ({"X-User-Id": "alice"}, {"scope": "user", "scope_id": "bob"}, bob_id),
            ({"X-Thread-Id": "thr_a"}, {"scope": "thread", "scope_id": "thr_b"}, thr_b_id),
            (
                {"X-Project-Area": "area_a"},
                {"scope": "project_area", "scope_id": "area_b"},
                area_b_id,
            ),
        ]
        for attacker_headers, query_params, target_id in isolation_probes:
            g = client.get("/api/v1/memory", headers=attacker_headers, params=query_params)
            assert g.status_code == 200
            assert g.json()["items"] == []

            e_json = client.get(
                "/api/v1/memory/export",
                headers=attacker_headers,
                params={"format": "json", **query_params},
            )
            assert e_json.status_code == 200
            assert e_json.json()["items"] == []

            e_md = client.get(
                "/api/v1/memory/export",
                headers=attacker_headers,
                params={"format": "md", **query_params},
            )
            assert e_md.status_code == 200
            assert target_id not in e_md.text

            p = client.patch(
                f"/api/v1/memory/{target_id}",
                headers=attacker_headers,
                json={"revision": 1, "content": "Hijacked"},
            )
            assert p.status_code == 403, p.text

            d = client.delete(f"/api/v1/memory/{target_id}", headers=attacker_headers)
            assert d.status_code == 403, d.text

        # Spoofed POST into another agent_role/user/thread/project_area must return 403
        spoof_cases = [
            ({"X-User-Id": "alice"}, {"scope": "user", "scope_id": "bob"}),
            ({"X-Agent-Role": "bot_a"}, {"scope": "agent_role", "scope_id": "bot_b"}),
            ({"X-Thread-Id": "thr_a"}, {"scope": "thread", "scope_id": "thr_b"}),
            ({"X-Project-Area": "area_a"}, {"scope": "project_area", "scope_id": "area_b"}),
        ]
        for spoof_headers, scope_fields in spoof_cases:
            r_spoof = client.post(
                "/api/v1/memory",
                headers=spoof_headers,
                json={
                    **scope_fields,
                    "kind": "source_reference",
                    "title": "Spoof attempt",
                    "content": "Cross-tenant write attempt.",
                },
            )
            assert r_spoof.status_code == 403, r_spoof.text


def test_e2e_memory_validation_422_invalid_scope_kind_and_dated_observation(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        bad_payloads: list[dict[str, Any]] = [
            {
                "scope": "facility",
                "scope_id": "plant_1",
                "kind": "preference",
                "title": "Bad scope",
                "content": "Invalid scope name.",
            },
            {
                "scope": "user",
                "scope_id": "alice",
                "kind": "episodic",
                "title": "Bad kind",
                "content": "Invalid kind name.",
            },
            {
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Missing valid_until",
                "content": "Missing TTL.",
                "observed_at": "2026-11-26T08:00:00Z",
            },
            {
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Missing observed_at",
                "content": "Missing observed_at.",
                "valid_until": "2099-01-01T00:00:00Z",
            },
            {
                "scope": "user",
                "scope_id": "alice",
                "kind": "dated_observation",
                "title": "Malformed timestamp",
                "content": "Bad timestamp.",
                "observed_at": "not-a-timestamp",
                "valid_until": "2099-01-01T00:00:00Z",
            },
            {
                "scope": "user",
                "scope_id": "alice",
                "kind": "preference",
                "title": "   ",
                "content": "Blank title.",
            },
        ]
        for payload in bad_payloads:
            resp = client.post("/api/v1/memory", headers=headers, json=payload)
            assert resp.status_code == 422, f"Expected 422 for {payload}: {resp.status_code}"


def test_e2e_memory_patch_and_delete_nonexistent_id_return_404(
    server: IsolatedServer,
) -> None:
    headers = {"X-User-Id": "alice"}
    with server.client() as client:
        r_patch = client.patch(
            "/api/v1/memory/mem_nonexistent_999",
            headers=headers,
            json={"revision": 1, "content": "No such item"},
        )
        assert r_patch.status_code == 404, r_patch.text
        assert "Memory item not found" in str(r_patch.json().get("detail", ""))

        r_del = client.delete("/api/v1/memory/mem_nonexistent_999", headers=headers)
        assert r_del.status_code == 404, r_del.text
        assert "Memory item not found" in str(r_del.json().get("detail", ""))


# ---------------------------------------------------------------------------
# Features #5 & #7 — SQLite WAL 8-Thread Concurrency & AuditLog SHA-256 Chain
# ---------------------------------------------------------------------------


def test_e2e_wal_8_thread_concurrent_writes_and_reads(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="wal_8t")
    with srv.client() as client:
        initial_usage = client.get("/api/v1/usage").json()

    rounds_per_thread = 4
    num_threads = 8

    def _worker(worker_idx: int) -> list[str]:
        worker_errors: list[str] = []
        with httpx.Client(
            base_url=srv.base_url,
            headers=srv.auth_headers(),
            timeout=20.0,
        ) as client:
            for round_idx in range(rounds_per_thread):
                tag = f"w{worker_idx}-r{round_idx}"
                try:
                    r_bot = client.post(
                        "/api/v1/bots",
                        json={"name": f"WAL Bot {tag}", "role_prompt": f"Worker {tag}"},
                    )
                    if r_bot.status_code != 201:
                        worker_errors.append(
                            f"POST /bots {tag} -> {r_bot.status_code}: {r_bot.text}"
                        )
                        continue
                    bot_data = r_bot.json()

                    r_set = client.patch(
                        "/api/v1/settings",
                        json={"display_name": f"Op-{tag}"},
                    )
                    if r_set.status_code != 200:
                        worker_errors.append(
                            f"PATCH /settings {tag} -> {r_set.status_code}: {r_set.text}"
                        )

                    r_apr = client.post(
                        "/api/v1/approvals",
                        json={
                            "bot_id": bot_data["id"],
                            "thread_id": bot_data["thread_id"],
                            "title": f"WAL Approval {tag}",
                            "arguments": {"step": tag},
                        },
                    )
                    if r_apr.status_code != 201:
                        worker_errors.append(
                            f"POST /approvals {tag} -> {r_apr.status_code}: {r_apr.text}"
                        )
                        continue
                    apr_id = r_apr.json()["id"]

                    r_res = client.post(
                        f"/api/v1/approvals/{apr_id}/resolve",
                        headers={"Idempotency-Key": f"wal-idem-{tag}"},
                        json={"decision": "allow_once"},
                    )
                    if r_res.status_code != 200:
                        worker_errors.append(
                            f"POST /approvals/resolve {tag} -> {r_res.status_code}: {r_res.text}"
                        )

                    r_list = client.get("/api/v1/bots")
                    if r_list.status_code != 200:
                        worker_errors.append(
                            f"GET /bots {tag} -> {r_list.status_code}: {r_list.text}"
                        )

                    r_usage = client.get("/api/v1/usage")
                    if r_usage.status_code != 200:
                        worker_errors.append(
                            f"GET /usage {tag} -> {r_usage.status_code}: {r_usage.text}"
                        )
                except Exception as exc:  # noqa: BLE001
                    worker_errors.append(f"Exception {tag}: {exc!r}")
        return worker_errors

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        results = list(pool.map(_worker, range(num_threads)))

    all_errors = [err for worker_errs in results for err in worker_errs]
    assert all_errors == [], f"Concurrent WAL errors: {all_errors}"

    expected_delta = num_threads * rounds_per_thread  # 32 (< MAX_ROSTER_ITEMS = 50)
    with srv.client() as client:
        final_usage = client.get("/api/v1/usage").json()
        assert final_usage["bots_count"] == initial_usage["bots_count"] + expected_delta
        assert final_usage["approvals_count"] == initial_usage["approvals_count"] + expected_delta

    srv.stop()

    conn = sqlite3.connect(srv.workspace_db_path)
    try:
        mode_row = conn.execute("PRAGMA journal_mode;").fetchone()
        assert mode_row is not None and str(mode_row[0]).lower() == "wal"
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        audit_res = store.verify_audit_chain()
        assert audit_res["valid"] is True
        assert audit_res["broken_seq"] is None
        assert audit_res["checked"] >= expected_delta * 3  # settings + create_apr + resolve_apr
    finally:
        store.close()


def test_e2e_wal_8_thread_concurrent_pages_drafts_and_threads_mix(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        initial_usage = client.get("/api/v1/usage").json()

    rounds_per_thread = 4
    num_threads = 8

    def _worker(worker_idx: int) -> list[str]:
        errs: list[str] = []
        with httpx.Client(
            base_url=server.base_url,
            headers=server.auth_headers(),
            timeout=20.0,
        ) as client:
            for round_idx in range(rounds_per_thread):
                tag = f"mix-{worker_idx}-{round_idx}"
                try:
                    r_drf = client.post(
                        "/api/v1/drafts",
                        json={
                            "bot_id": "bot_chief",
                            "thread_id": "thr_bot_chief",
                            "channel_type": "email",
                            "fields": {"to": "ops@plant.local", "subject": f"Initial {tag}"},
                        },
                    )
                    if r_drf.status_code != 201:
                        errs.append(f"POST /drafts {tag} -> {r_drf.status_code}: {r_drf.text}")
                        continue
                    draft_id = r_drf.json()["id"]

                    r_drf_res = client.post(
                        f"/api/v1/drafts/{draft_id}/resolve",
                        headers={"Idempotency-Key": f"idem-draft-{tag}"},
                        json={"action": "send", "fields": {"subject": f"Sent {tag}"}},
                    )
                    if r_drf_res.status_code != 200:
                        errs.append(
                            f"POST /drafts/resolve {tag} -> "
                            f"{r_drf_res.status_code}: {r_drf_res.text}"
                        )

                    r_page = client.post(
                        "/api/v1/pages",
                        json={
                            "bot_id": "bot_chief",
                            "thread_id": "thr_bot_chief",
                            "title": f"Concurrent Page {tag}",
                            "content_md": f"# Report {tag}\nInitial body.",
                        },
                    )
                    if r_page.status_code != 201:
                        errs.append(f"POST /pages {tag} -> {r_page.status_code}: {r_page.text}")
                        continue
                    page_id = r_page.json()["id"]

                    r_patch = client.patch(
                        f"/api/v1/pages/{page_id}",
                        json={"content_md": f"# Report {tag}\nUpdated body."},
                    )
                    if r_patch.status_code != 200:
                        errs.append(
                            f"PATCH /pages {tag} -> {r_patch.status_code}: {r_patch.text}"
                        )

                    r_msgs = client.get("/api/v1/threads/thr_bot_chief/messages")
                    if r_msgs.status_code != 200:
                        errs.append(f"GET /messages {tag} -> {r_msgs.status_code}: {r_msgs.text}")

                    r_lib = client.get("/api/v1/bots/bot_chief/library")
                    if r_lib.status_code != 200:
                        errs.append(f"GET /library {tag} -> {r_lib.status_code}: {r_lib.text}")
                except Exception as exc:  # noqa: BLE001
                    errs.append(f"Exception {tag}: {exc!r}")
        return errs

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        results = list(pool.map(_worker, range(num_threads)))

    all_errors = [err for worker_errs in results for err in worker_errs]
    assert all_errors == [], f"Concurrent mixed WAL errors: {all_errors}"

    expected_delta = num_threads * rounds_per_thread
    with server.client() as client:
        final_usage = client.get("/api/v1/usage").json()
        assert final_usage["pages_count"] == initial_usage["pages_count"] + expected_delta

        lib = client.get("/api/v1/bots/bot_chief/library", params={"type": "page"}).json()
        page_titles = {item["title"] for item in lib["items"]}
        for w in range(num_threads):
            for r in range(rounds_per_thread):
                assert f"Concurrent Page mix-{w}-{r}" in page_titles


def test_e2e_wal_multi_connection_concurrent_writers_and_server_reads(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    from src.web.v1.store import WorkspaceStore

    srv = server_factory(name="wal_multiconn")
    with srv.client() as client:
        initial_usage = client.get("/api/v1/usage").json()

    num_http_workers = 4
    num_direct_workers = 4
    rounds = 4

    direct_stores = [WorkspaceStore(srv.workspace_db_path) for _ in range(num_direct_workers)]
    try:

        def _http_worker(worker_idx: int) -> list[str]:
            errs: list[str] = []
            with httpx.Client(
                base_url=srv.base_url,
                headers=srv.auth_headers(),
                timeout=20.0,
            ) as client:
                for round_idx in range(rounds):
                    tag = f"http-{worker_idx}-{round_idx}"
                    try:
                        r_get_bots = client.get("/api/v1/bots")
                        if r_get_bots.status_code != 200:
                            errs.append(f"GET /bots {tag} -> {r_get_bots.status_code}")

                        r_patch_set = client.patch(
                            "/api/v1/settings",
                            json={"display_name": f"HTTP-{tag}"},
                        )
                        if r_patch_set.status_code != 200:
                            errs.append(
                                f"PATCH /settings {tag} -> "
                                f"{r_patch_set.status_code}: {r_patch_set.text}"
                            )

                        r_post_apr = client.post(
                            "/api/v1/approvals",
                            json={
                                "bot_id": "bot_chief",
                                "thread_id": "thr_bot_chief",
                                "title": f"MultiConn HTTP {tag}",
                                "arguments": {"tag": tag},
                            },
                        )
                        if r_post_apr.status_code != 201:
                            errs.append(
                                f"POST /approvals {tag} -> "
                                f"{r_post_apr.status_code}: {r_post_apr.text}"
                            )

                        r_get_set = client.get("/api/v1/settings")
                        if r_get_set.status_code != 200:
                            errs.append(f"GET /settings {tag} -> {r_get_set.status_code}")
                    except Exception as exc:  # noqa: BLE001
                        errs.append(f"HTTP exc {tag}: {exc!r}")
            return errs

        def _direct_writer(worker_idx: int) -> list[str]:
            errs: list[str] = []
            ext_store = direct_stores[worker_idx]
            for round_idx in range(rounds):
                tag = f"direct-{worker_idx}-{round_idx}"
                try:
                    ext_store.update_settings({"display_name": f"Direct-{tag}"})
                    ext_store.create_approval(
                        bot_id="bot_chief",
                        thread_id="thr_bot_chief",
                        title=f"MultiConn Direct {tag}",
                        arguments={"tag": tag},
                    )
                except Exception as exc:  # noqa: BLE001
                    errs.append(f"Direct WAL exc {tag}: {exc!r}")
            return errs

        with ThreadPoolExecutor(max_workers=num_http_workers + num_direct_workers) as pool:
            http_futs = [pool.submit(_http_worker, i) for i in range(num_http_workers)]
            direct_futs = [pool.submit(_direct_writer, i) for i in range(num_direct_workers)]
            all_errors = [
                err
                for fut in [*http_futs, *direct_futs]
                for err in fut.result()
            ]

        assert all_errors == [], f"Multi-connection WAL contention errors: {all_errors}"
    finally:
        for ext_store in direct_stores:
            ext_store.close()

    expected_approvals_delta = (num_http_workers + num_direct_workers) * rounds
    with srv.client() as client:
        final_usage = client.get("/api/v1/usage").json()
        assert (
            final_usage["approvals_count"]
            == initial_usage["approvals_count"] + expected_approvals_delta
        )

    srv.stop()

    conn = sqlite3.connect(srv.workspace_db_path)
    try:
        mode_row = conn.execute("PRAGMA journal_mode;").fetchone()
        assert mode_row is not None and str(mode_row[0]).lower() == "wal"
    finally:
        conn.close()

    verify_store = WorkspaceStore(srv.workspace_db_path)
    try:
        audit_res = verify_store.verify_audit_chain()
        assert audit_res["valid"] is True
        assert audit_res["broken_seq"] is None
        assert audit_res["checked"] >= expected_approvals_delta * 2
    finally:
        verify_store.close()


# ---------------------------------------------------------------------------
# Feature #7 — SHA-256 Hash-Chained AuditLog Tier 1
# ---------------------------------------------------------------------------


def test_e2e_audit_chain_integrity_and_secret_scrubbing_after_api_mutations(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="audit_chain")
    vault_secret_pw = "AuditSecretPass99!"

    with srv.client() as client:
        r_set = client.patch("/api/v1/settings", json={"display_name": "Chain Inspector"})
        assert r_set.status_code == 200, r_set.text

        r_apr = client.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Inspect audit approval",
                "arguments": {"api_key": "sk-audit-arg-secret-123456"},
            },
        )
        assert r_apr.status_code == 201, r_apr.text
        apr_id = r_apr.json()["id"]

        r_res = client.post(
            f"/api/v1/approvals/{apr_id}/resolve",
            headers={"Idempotency-Key": "idem-audit-chain-1"},
            json={"decision": "allow_once"},
        )
        assert r_res.status_code == 200, r_res.text

        r_vlt = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "Audit SCADA Login",
                "domain": "scada.local",
                "fields": {"username": "plant_admin", "password": vault_secret_pw},
            },
        )
        assert r_vlt.status_code == 201, r_vlt.text

        r_bot = client.post("/api/v1/bots", json={"name": "Audit Disposable Bot"})
        assert r_bot.status_code == 201, r_bot.text
        bot_id = r_bot.json()["id"]

        r_del_bot = client.delete(f"/api/v1/bots/{bot_id}")
        assert r_del_bot.status_code == 200, r_del_bot.text

    srv.stop()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is True
        assert res["checked"] >= 5
        assert res["broken_seq"] is None
        assert res["reason"] is None
        assert isinstance(res["head_hash"], str) and len(res["head_hash"]) == 64

        audit_rows = store.list_audit_events(limit=100)
        serialized = json.dumps(audit_rows)
        assert vault_secret_pw not in serialized
        assert "sk-audit-arg-secret-123456" not in serialized
    finally:
        store.close()


def test_e2e_audit_log_vault_create_and_delete_events(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="audit_vault")
    vault_pw = "VaultAuditSecret42!"

    with srv.client() as client:
        r_vlt = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "Audit PLC HMI",
                "domain": "hmi.local",
                "fields": {"username": "hmi_op", "password": vault_pw},
            },
        )
        assert r_vlt.status_code == 201, r_vlt.text
        sec_id = str(r_vlt.json()["id"])

        r_del = client.delete(f"/api/v1/vault/secrets/{sec_id}")
        assert r_del.status_code == 200, r_del.text

    srv.stop()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is True
        assert res["broken_seq"] is None
        assert res["reason"] is None
        assert res["checked"] >= 2

        rows = store.list_audit_events(limit=50)
        create_rows = [
            r
            for r in rows
            if r["action"] == "vault.create"
            and r["entity_type"] == "vault_secret"
            and r["entity_id"] == sec_id
        ]
        delete_rows = [
            r
            for r in rows
            if r["action"] == "vault.delete"
            and r["entity_type"] == "vault_secret"
            and r["entity_id"] == sec_id
        ]
        assert len(create_rows) == 1
        assert len(delete_rows) == 1
        assert create_rows[0]["decision"] == "allow"
        assert delete_rows[0]["decision"] == "allow"
        assert int(create_rows[0]["seq"]) < int(delete_rows[0]["seq"])
        assert vault_pw not in json.dumps(rows)
    finally:
        store.close()


def test_e2e_audit_log_artifact_delete_and_auto_review_replace_events(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="audit_art_autorev")

    with srv.client() as client:
        r_att = client.post(
            "/api/v1/attachments",
            params={"filename": "audit_artifact.txt", "thread_id": "thr_bot_chief"},
            content=b"audit artifact payload",
            headers={"Content-Type": "text/plain"},
        )
        assert r_att.status_code == 201, r_att.text

        lib_items = client.get(
            "/api/v1/bots/bot_chief/library", params={"type": "file"}
        ).json()["items"]
        art = next(item for item in lib_items if item["title"] == "audit_artifact.txt")
        art_id = str(art["id"])

        r_del_art = client.delete(f"/api/v1/artifacts/{art_id}")
        assert r_del_art.status_code == 200, r_del_art.text

        r_auto = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"bucket": "allow_auto", "rule_text": "Allow read-only diagnostics"},
                ]
            },
        )
        assert r_auto.status_code == 200, r_auto.text

    srv.stop()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is True
        assert res["broken_seq"] is None
        assert res["reason"] is None
        assert res["checked"] >= 2

        rows = store.list_audit_events(limit=50)
        art_rows = [
            r
            for r in rows
            if r["action"] == "artifact.delete"
            and r["entity_type"] == "artifact"
            and r["entity_id"] == art_id
        ]
        auto_rows = [
            r
            for r in rows
            if r["action"] == "auto_review.replace"
            and r["entity_type"] == "auto_review_rule"
        ]
        assert len(art_rows) == 1
        assert art_rows[0]["decision"] == "allow"
        assert len(auto_rows) == 1
        assert auto_rows[0]["decision"] == "allow"
        assert auto_rows[0]["detail"].get("count") == 1
    finally:
        store.close()


def test_e2e_audit_log_draft_resolve_and_connected_app_update_events(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(name="audit_draft_app")

    with srv.client() as client:
        r_drf = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "channel_type": "email",
                "fields": {"to": "ops@plant.local", "subject": "Shift log"},
            },
        )
        assert r_drf.status_code == 201, r_drf.text
        draft_id = str(r_drf.json()["id"])

        r_res = client.post(
            f"/api/v1/drafts/{draft_id}/resolve",
            headers={"Idempotency-Key": f"idem-audit-{draft_id}"},
            json={"action": "send", "fields": {"subject": "Approved shift log"}},
        )
        assert r_res.status_code == 200, r_res.text

        r_app = client.patch(
            "/api/v1/apps/app_agy",
            json={"account_label": "Audit Station 7"},
        )
        assert r_app.status_code == 200, r_app.text

    srv.stop()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is True
        assert res["broken_seq"] is None
        assert res["reason"] is None
        assert res["checked"] >= 2

        rows = store.list_audit_events(limit=50)
        draft_rows = [
            r
            for r in rows
            if r["action"] == "draft.resolve"
            and r["entity_type"] == "draft"
            and r["entity_id"] == draft_id
        ]
        app_rows = [
            r
            for r in rows
            if r["action"] == "connected_app.update"
            and r["entity_type"] == "connected_app"
            and r["entity_id"] == "app_agy"
        ]
        assert len(draft_rows) == 1
        assert draft_rows[0]["decision"] == "send"
        assert len(app_rows) == 1
        assert app_rows[0]["decision"] == "allow"
        assert app_rows[0]["detail"].get("account_label") == "Audit Station 7"
    finally:
        store.close()


def test_e2e_audit_log_empty_and_single_row_chain_verification(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    from src.storage.audit_chain import GENESIS_PREV_HASH
    from src.web.v1.store import WorkspaceStore

    empty_store = WorkspaceStore(tmp_path / "empty_audit_workspace.sqlite3")
    try:
        assert empty_store.list_audit_events(limit=10) == []
        empty_res = empty_store.verify_audit_chain()
        assert empty_res["valid"] is True
        assert empty_res["checked"] == 0
        assert empty_res["broken_seq"] is None
        assert empty_res["reason"] is None
        assert empty_res["head_hash"] == GENESIS_PREV_HASH
    finally:
        empty_store.close()

    srv = server_factory(name="audit_single")
    with srv.client() as client:
        r_set = client.patch(
            "/api/v1/settings",
            json={"display_name": "Single Row Operator"},
        )
        assert r_set.status_code == 200, r_set.text
    srv.stop()

    single_store = WorkspaceStore(srv.workspace_db_path)
    try:
        rows = single_store.list_audit_events(limit=10)
        assert len(rows) == 1
        row = rows[0]
        assert row["seq"] == 1
        assert row["prev_hash"] == GENESIS_PREV_HASH
        assert row["action"] == "settings.update"
        assert row["entity_type"] == "settings"
        assert row["entity_id"] == "default"

        single_res = single_store.verify_audit_chain()
        assert single_res["valid"] is True
        assert single_res["checked"] == 1
        assert single_res["broken_seq"] is None
        assert single_res["reason"] is None
        assert single_res["head_hash"] == row["entry_hash"]
    finally:
        single_store.close()


# ---------------------------------------------------------------------------
# Feature #7 — SHA-256 Hash-Chained AuditLog Tier 2 (Tamper Detection)
# ---------------------------------------------------------------------------


def test_e2e_audit_log_append_only_triggers_block_update_and_delete(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="audit_trig")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "trig_copy_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE workspace_audit_log SET decision = 'forged' WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM workspace_audit_log WHERE seq = 1")
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(srv.workspace_db_path)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is True
        assert res["checked"] >= 3
    finally:
        store.close()


def test_e2e_audit_log_tamper_field_detection_entry_hash_mismatch(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="tamper_field")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "tamper_field_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        count_row = conn.execute("SELECT COUNT(*) FROM workspace_audit_log").fetchone()
        assert count_row is not None and int(count_row[0]) >= 3
        conn.execute("DROP TRIGGER trg_workspace_audit_log_no_update")
        conn.execute("UPDATE workspace_audit_log SET decision = 'forged' WHERE seq = 2")
        conn.commit()
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(tamper_db)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is False
        assert res["broken_seq"] == 2
        assert res["reason"] == "entry_hash_mismatch"
    finally:
        store.close()


def test_e2e_audit_log_tamper_middle_row_deletion_sequence_gap(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="tamper_gap")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "tamper_gap_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        count_row = conn.execute("SELECT COUNT(*) FROM workspace_audit_log").fetchone()
        assert count_row is not None and int(count_row[0]) >= 3
        conn.execute("DROP TRIGGER trg_workspace_audit_log_no_delete")
        conn.execute("DELETE FROM workspace_audit_log WHERE seq = 2")
        conn.commit()
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(tamper_db)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is False
        assert res["broken_seq"] == 2
        assert res["reason"] == "sequence_gap"
    finally:
        store.close()


def test_e2e_audit_log_tamper_tail_row_deletion_tail_truncation(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="tamper_tail")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "tamper_tail_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        count_row = conn.execute("SELECT COUNT(*) FROM workspace_audit_log").fetchone()
        assert count_row is not None and int(count_row[0]) >= 3
        conn.execute("DROP TRIGGER trg_workspace_audit_log_no_delete")
        conn.execute(
            "DELETE FROM workspace_audit_log WHERE seq = (SELECT MAX(seq) FROM workspace_audit_log)"
        )
        conn.commit()
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(tamper_db)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is False
        assert res["reason"] == "tail_truncation"
    finally:
        store.close()


def test_e2e_audit_log_tamper_prev_hash_mismatch(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="tamper_prev")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "tamper_prev_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        count_row = conn.execute("SELECT COUNT(*) FROM workspace_audit_log").fetchone()
        assert count_row is not None and int(count_row[0]) >= 3
        conn.execute("DROP TRIGGER trg_workspace_audit_log_no_update")
        conn.execute(
            "UPDATE workspace_audit_log SET prev_hash = ? WHERE seq = 2",
            ("a" * 64,),
        )
        conn.commit()
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(tamper_db)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is False
        assert res["broken_seq"] == 2
        assert res["reason"] == "prev_hash_mismatch"
    finally:
        store.close()


def test_e2e_audit_log_tamper_kv_meta_head_hash_mismatch(
    server_factory: Callable[..., IsolatedServer],
    tmp_path: Path,
) -> None:
    srv = server_factory(name="tamper_head")
    _seed_audit_mutations(srv)
    srv.stop()

    tamper_db = _copy_workspace_db(
        srv.workspace_db_path, tmp_path / "tamper_head_workspace.sqlite3"
    )
    conn = sqlite3.connect(tamper_db)
    try:
        count_row = conn.execute("SELECT COUNT(*) FROM workspace_audit_log").fetchone()
        assert count_row is not None and int(count_row[0]) >= 3
        conn.execute(
            "UPDATE kv_meta SET value = ? WHERE key = 'audit_head_hash'",
            ("f" * 64,),
        )
        conn.commit()
    finally:
        conn.close()

    from src.web.v1.store import WorkspaceStore

    store = WorkspaceStore(tamper_db)
    try:
        res = store.verify_audit_chain()
        assert res["valid"] is False
        assert res["reason"] == "head_hash_mismatch"
    finally:
        store.close()
