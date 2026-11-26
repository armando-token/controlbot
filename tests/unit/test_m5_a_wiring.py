"""Unit tests for Milestone M5 Track A cross-module wiring and security fixes."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, field_validator
from src.storage.memory import MemoryStore
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    is_sensitive_key_strict,
)
from src.web.app import create_app
from src.web.protocols import maybe_await


class _ValidatorProbe(BaseModel):
    secret_value: str

    @field_validator("secret_value")
    @classmethod
    def _reject_secret(cls, value: str) -> str:
        raise ValueError(f"Rejected raw secret: {value}")


@pytest.mark.n1
def test_redaction_strict_recognizes_vault_keys_without_breaking_query_probe() -> None:
    for key in (
        "secret_value",
        "secretValue",
        "secret-value",
        "vault_value",
        "vaultValue",
        "my_vault_value",
        "passphrase",
        "sshPassphrase",
        "private_pem",
        "tls_private_pem",
    ):
        assert is_sensitive_key_strict(key) is True, f"Expected sensitive key: {key}"

    assert is_sensitive_key_strict("display_name") is False
    assert is_sensitive_key_strict("value") is False
    assert contains_unredacted_secret_strict("token=REAL_SECRET") is True
    assert contains_unredacted_secret_strict("token=[REDACTED]") is False


@pytest.mark.n1
async def test_create_app_wires_memory_event_bus_runner_and_lifespan_close(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "workspace.sqlite3"
    app1 = create_app(db_path=db_path)

    assert isinstance(app1.state.memory_store, MemoryStore)
    assert app1.state.v1_runner._memory_store is app1.state.memory_store
    assert app1.state.v1_runner._computer_gateway is app1.state.computer_gateway
    epoch_1 = app1.state.event_bus.epoch

    mem_close_calls = 0
    bus_close_calls = 0
    orig_mem_close = app1.state.memory_store.close
    orig_bus_close = app1.state.event_bus.close

    def _tracked_mem_close() -> None:
        nonlocal mem_close_calls
        mem_close_calls += 1
        orig_mem_close()

    def _tracked_bus_close() -> None:
        nonlocal bus_close_calls
        bus_close_calls += 1
        orig_bus_close()

    app1.state.memory_store.close = _tracked_mem_close
    app1.state.event_bus.close = _tracked_bus_close

    async with app1.router.lifespan_context(app1):
        transport = httpx.ASGITransport(app=app1)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            create_resp = await client.post(
                "/api/v1/memory",
                json={
                    "scope": "user",
                    "scope_id": "operator",
                    "kind": "preference",
                    "title": "Preferred unit",
                    "content": "Always report pressure in bar.",
                },
            )
            assert create_resp.status_code == 201
            chain_res = app1.state.workspace_store.verify_audit_chain()
            assert chain_res["valid"] is True
            assert chain_res["checked"] >= 1

    assert mem_close_calls == 1
    assert bus_close_calls == 1

    # Re-opening against same DB preserves EventBus epoch across restart
    app2 = create_app(db_path=db_path)
    try:
        assert app2.state.event_bus.epoch == epoch_1
    finally:
        app2.state.memory_store.close()
        app2.state.event_bus.close()
        app2.state.workspace_store.close()


@pytest.mark.n1
async def test_validation_422_redacts_vault_and_secure_form_secrets(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "vault_422.sqlite3")
    secret_a = "UltraSecretValueAlpha123!"
    secret_b = "UltraSecretValueBeta456!"
    long_a = secret_a * 400
    long_b = secret_b * 400

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            r1 = await client.post(
                "/api/v1/vault/secrets",
                json={"name": "TooLongSecretValue", "secret_value": long_a},
            )
            assert r1.status_code == 422
            assert secret_a not in r1.text
            assert r1.json()["detail"][0]["input"] == "[REDACTED]"

            r2 = await client.post(
                "/api/v1/vault/secrets",
                json={"name": "TooLongValue", "value": long_b},
            )
            assert r2.status_code == 422
            assert secret_b not in r2.text
            assert r2.json()["detail"][0]["input"] == "[REDACTED]"

            r3 = await client.post(
                "/api/v1/vault/secure-fill",
                json={"values": {"custom_field": [secret_a]}},
            )
            assert r3.status_code == 422
            assert secret_a not in r3.text

            # Model-validator 422 where loc == ["body"] and input is a dict
            r4 = await client.post(
                "/api/v1/vault/secrets",
                json={"name": "InvalidType", "secret_value": secret_a, "fields": ["bad"]},
            )
            assert r4.status_code == 422
            assert secret_a not in r4.text

            r5 = await client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "title": "",
                    "fields": {"nested_secret": secret_b},
                },
            )
            assert r5.status_code == 422
            assert secret_b not in r5.text
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_post_thread_message_forwards_page_context_id(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "page_ctx.sqlite3")
    captured: dict[str, Any] = {}

    def _fake_start_turn(**kwargs: Any) -> str:
        captured.update(kwargs)
        return "trn_test_page_ctx"

    try:
        with patch.object(app.state.v1_runner, "start_turn", side_effect=_fake_start_turn):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                resp = await client.post(
                    "/api/v1/threads/thr_bot_chief/messages",
                    json={"content": "Summarize this page", "page_context_id": "pag_demo123"},
                )
        assert resp.status_code == 202
        assert captured["page_context_id"] == "pag_demo123"
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_draft_webhook_auto_vaults_and_delivers_hmac_on_resolve(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "draft_wh.sqlite3")
    received: list[tuple[str, bytes]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def receive(request: Request) -> JSONResponse:
        body = await request.body()
        received.append((request.headers.get("x-controlbot-signature", ""), body))
        return JSONResponse({"ok": True})

    wh_transport = httpx.ASGITransport(app=wh_app)

    class _MockAsyncClient(httpx.AsyncClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("trust_env", None)
            kwargs["transport"] = wh_transport
            super().__init__(*args, **kwargs)

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            c_resp = await client.post(
                "/api/v1/drafts",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "channel_type": "webhook",
                    "fields": {
                        "webhook_url": "http://mock-wh/hook",
                        "webhook_secret": "hmac-secret-1",
                        "body": "Pump report",
                    },
                },
            )
            assert c_resp.status_code == 201
            draft = c_resp.json()
            assert draft["fields"]["webhook_secret"] == "[REDACTED]"
            sec_id = draft["fields"].get("webhook_secret_id")
            assert isinstance(sec_id, str) and sec_id.startswith("vlt_")
            assert "hmac-secret-1" not in c_resp.text

            # Update webhook_secret via resolve_draft(action="update") -> re-vaults under bot_id
            u_resp = await client.post(
                f"/api/v1/drafts/{draft['id']}/resolve",
                json={"action": "update", "fields": {"webhook_secret": "hmac-secret-2"}},
            )
            assert u_resp.status_code == 200
            updated_sec_id = u_resp.json()["fields"].get("webhook_secret_id")
            assert isinstance(updated_sec_id, str) and updated_sec_id != sec_id
            assert "hmac-secret-2" not in u_resp.text

            with patch("src.web.v1.runner.httpx.AsyncClient", _MockAsyncClient):
                s_resp = await client.post(
                    f"/api/v1/drafts/{draft['id']}/resolve",
                    json={"action": "send"},
                )
            assert s_resp.status_code == 200
            assert len(received) == 1
            sig, raw_body = received[0]
            expected_sig = (
                "sha256="
                + hmac.new(b"hmac-secret-2", raw_body, hashlib.sha256).hexdigest()
            )
            assert sig == expected_sig
            parsed_body = json.loads(raw_body.decode("utf-8"))
            assert parsed_body["fields"]["webhook_secret"] == "[REDACTED]"
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_secure_fill_secret_only_form_fails_closed_when_not_saved(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "secret_form.sqlite3")
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            f_no_save = (
                await client.post(
                    "/api/v1/secure-forms",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "secret",
                        "domain": "api.internal",
                        "title": "Read-only Secret",
                        "fields": [{"name": "api_key", "label": "Key", "secret": True}],
                        "allow_vault_save": False,
                    },
                )
            ).json()
            r_409 = await client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": f_no_save["id"],
                    "bot_id": "bot_chief",
                    "values": {"api_key": "k-123"},
                    "save_to_vault": True,
                },
            )
            assert r_409.status_code == 409
            assert app.state.workspace_store.get_secure_form(f_no_save["id"])["status"] == "pending"

            f_allow = (
                await client.post(
                    "/api/v1/secure-forms",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "secret",
                        "domain": "api.internal",
                        "title": "Saveable Secret",
                        "fields": [{"name": "api_key", "label": "Key", "secret": True}],
                        "allow_vault_save": True,
                    },
                )
            ).json()
            r_422_nosave = await client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": f_allow["id"],
                    "bot_id": "bot_chief",
                    "values": {"api_key": "k-123"},
                    "save_to_vault": False,
                },
            )
            assert r_422_nosave.status_code == 422
            assert app.state.workspace_store.get_secure_form(f_allow["id"])["status"] == "pending"

            r_422_empty = await client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": f_allow["id"],
                    "bot_id": "bot_chief",
                    "values": {},
                    "save_to_vault": True,
                },
            )
            assert r_422_empty.status_code == 422
            assert app.state.workspace_store.get_secure_form(f_allow["id"])["status"] == "pending"

            r_ok = await client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": f_allow["id"],
                    "bot_id": "bot_chief",
                    "values": {"api_key": "k-123"},
                    "save_to_vault": True,
                },
            )
            assert r_ok.status_code == 200
            body = r_ok.json()
            assert body["saved_secret_id"] is not None
            assert "Secret saved." in body["message"]
            assert (
                app.state.workspace_store.get_secure_form(f_allow["id"])["status"] == "submitted"
            )
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_delete_artifact_dict_with_none_attachment_path_skips_fallback_unlink(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "art_del.sqlite3")
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            up = await client.post(
                "/api/v1/attachments",
                params={"filename": "bound.txt", "thread_id": "thr_bot_chief"},
                content=b"keep-me",
                headers={"Content-Type": "text/plain"},
            )
            assert up.status_code == 201
            att_id = up.json()["id"]
            att_rec = app.state.workspace_store.get_attachment_record(att_id)
            assert att_rec is not None
            disk_path = Path(str(att_rec["storage_path"]))
            assert disk_path.is_file()

            lib = await client.get("/api/v1/bots/bot_chief/library")
            art_id = next(
                it["id"]
                for it in lib.json()["items"]
                if it.get("url") == f"/api/v1/attachments/{att_id}"
            )

            with patch.object(
                app.state.workspace_store,
                "delete_artifact",
                return_value={"deleted": True, "attachment_path": None},
            ):
                del_resp = await client.delete(f"/api/v1/artifacts/{art_id}")
            assert del_resp.status_code == 200
            assert disk_path.is_file()
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_memory_routes_block_body_actor_role_manager_spoofing(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "mem_acl.sqlite3")
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Body actor_role="Manager" without header/query -> 403 even on user scope
            r_spoof_user = await client.post(
                "/api/v1/memory",
                json={
                    "scope": "user",
                    "scope_id": "operator",
                    "kind": "preference",
                    "title": "Spoof attempt",
                    "content": "Attempt escalation",
                    "actor_role": "Manager",
                },
            )
            assert r_spoof_user.status_code == 403

            # 2. Body actor_role="Manager" on org_approved without header/query -> 403
            r_spoof_org = await client.post(
                "/api/v1/memory",
                json={
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": "Org SOP",
                    "content": "Standard procedure",
                    "actor_role": "Manager",
                },
            )
            assert r_spoof_org.status_code == 403

            # 3. Query param ?actor_role=Manager (used by MemoryModal.tsx) -> 201
            r_query_mgr = await client.post(
                "/api/v1/memory?actor_role=Manager",
                json={
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": "Org SOP",
                    "content": "Verify valve before lockout.",
                    "actor_role": "Manager",
                },
            )
            assert r_query_mgr.status_code == 201
            item_id = r_query_mgr.json()["id"]

            # 4. PATCH with body actor_role="Manager" without header/query -> 403
            r_patch_spoof = await client.patch(
                f"/api/v1/memory/{item_id}",
                json={
                    "revision": 1,
                    "content": "Tampered",
                    "actor_role": "Manager",
                },
            )
            assert r_patch_spoof.status_code == 403

            # 5. PATCH with X-Actor-Role: Manager header -> 200
            r_patch_hdr = await client.patch(
                f"/api/v1/memory/{item_id}",
                headers={"X-Actor-Role": "Manager"},
                json={"revision": 1, "content": "Verified SOP update."},
            )
            assert r_patch_hdr.status_code == 200
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_alternating_workspace_and_memory_audit_writes_keep_chain_valid(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "audit_interleave.sqlite3")
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. WorkspaceStore write -> sets kv_meta audit_head_seq & audit_head_hash
            v_resp = await client.post(
                "/api/v1/vault/secrets",
                json={"name": "v1", "secret_value": "s1"},
            )
            assert v_resp.status_code == 201
            res1 = app.state.workspace_store.verify_audit_chain()
            assert res1["valid"] is True, res1

            # 2. MemoryStore create -> must keep kv_meta head synced
            m_create = await client.post(
                "/api/v1/memory",
                json={
                    "scope": "user",
                    "scope_id": "operator",
                    "kind": "preference",
                    "title": "Pressure Unit",
                    "content": "Report in bar.",
                },
            )
            assert m_create.status_code == 201
            mem_id = m_create.json()["id"]
            res2 = app.state.workspace_store.verify_audit_chain()
            assert res2["valid"] is True, res2

            # 3. MemoryStore promote_denied -> 403 audit row must keep chain valid
            m_deny = await client.post(
                "/api/v1/memory",
                json={
                    "scope": "user",
                    "scope_id": "operator",
                    "kind": "approved_procedure",
                    "title": "Unauthorized SOP",
                    "content": "Should fail.",
                },
            )
            assert m_deny.status_code == 403
            res3 = app.state.workspace_store.verify_audit_chain()
            assert res3["valid"] is True, res3
            assert res3["checked"] == 3

            # 4. WorkspaceStore audited write interleaved between memory ops
            d_resp = await client.post(
                "/api/v1/drafts",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "channel_type": "email",
                    "fields": {"to": "ops@example.com", "subject": "Check", "body": "OK"},
                },
            )
            assert d_resp.status_code == 201
            r_resp = await client.post(
                f"/api/v1/drafts/{d_resp.json()['id']}/resolve",
                json={"action": "discard"},
            )
            assert r_resp.status_code == 200
            res4 = app.state.workspace_store.verify_audit_chain()
            assert res4["valid"] is True, res4
            assert res4["checked"] == 4

            # 5. MemoryStore update
            m_patch = await client.patch(
                f"/api/v1/memory/{mem_id}",
                json={"revision": 1, "content": "Report in kPa."},
            )
            assert m_patch.status_code == 200
            res5 = app.state.workspace_store.verify_audit_chain()
            assert res5["valid"] is True, res5
            assert res5["checked"] == 5

            # 6. MemoryStore delete
            m_del = await client.delete(f"/api/v1/memory/{mem_id}")
            assert m_del.status_code == 200
            res6 = app.state.workspace_store.verify_audit_chain()
            assert res6["valid"] is True, res6
            assert res6["checked"] == 6

            # 7. Final WorkspaceStore audit write after memory delete
            app.state.workspace_store.append_audit_event(
                actor="operator",
                action="test.final",
                entity_type="test",
                entity_id="final",
            )
            res7 = app.state.workspace_store.verify_audit_chain()
            assert res7["valid"] is True, res7
            assert res7["checked"] == 7
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_validation_422_redacts_missing_fields_extra_keys_and_validator_messages(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "vault_422_exhaustive.sqlite3")
    secret_a = "LEAKED_VAULT_SECRET_12345!"
    secret_b = "TOP_SECRET_PROBE_9911"

    @app.post("/api/v1/vault/test-validator-probe")
    async def _validator_probe(payload: _ValidatorProbe) -> JSONResponse:
        return JSONResponse({"ok": payload.secret_value})

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Missing required 'name' with {"value": ...} -> loc=["body", "name"]
            r_miss_val = await client.post(
                "/api/v1/vault/secrets",
                json={"value": secret_a},
            )
            assert r_miss_val.status_code == 422
            assert secret_a not in r_miss_val.text
            assert r_miss_val.json()["detail"][0]["msg"] == "Field required"
            assert r_miss_val.json()["detail"][0]["input"]["value"] == "[REDACTED]"

            # 2. Missing required 'name' with {"fields": {"login_note": ...}}
            r_miss_fields = await client.post(
                "/api/v1/vault/secrets",
                json={"fields": {"login_note": secret_a}},
            )
            assert r_miss_fields.status_code == 422
            assert secret_a not in r_miss_fields.text
            assert r_miss_fields.json()["detail"][0]["msg"] == "Field required"
            assert r_miss_fields.json()["detail"][0]["input"]["fields"] == "[REDACTED]"

            # 3. Model-validator loc=["body"] with non-denylisted/plural keys
            for extra_payload in (
                {"name": "c1", "secretValues": {"k": secret_b}},
                {"name": "c2", "vaultValues": secret_b},
                {"name": "c3", "customNote": secret_b},
                {"name": "c4", "customNote": "secret"},
            ):
                r_extra = await client.post("/api/v1/vault/secrets", json=extra_payload)
                assert r_extra.status_code == 422
                assert secret_b not in r_extra.text
                body = r_extra.json()
                assert (
                    body["detail"][0]["msg"]
                    == "Value error, Vault secret requires either fields or secret_value."
                )

            # 4. Normal max_length message remains intact while secret is redacted
            r_len = await client.post(
                "/api/v1/vault/secrets",
                json={"name": "len_check", "secret_value": secret_b * 500},
            )
            assert r_len.status_code == 422
            assert secret_b not in r_len.text
            assert r_len.json()["detail"][0]["input"] == "[REDACTED]"
            assert (
                r_len.json()["detail"][0]["msg"]
                == "String should have at most 8000 characters"
            )

            # 5. Custom @field_validator embedding raw secret in ValueError message
            r_val_msg = await client.post(
                "/api/v1/vault/test-validator-probe",
                json={"secret_value": secret_b},
            )
            assert r_val_msg.status_code == 422
            assert secret_b not in r_val_msg.text
            detail = r_val_msg.json()["detail"][0]
            assert detail["input"] == "[REDACTED]"
            assert detail["msg"] == "Value error, Rejected raw secret: [REDACTED]"

            # 6. Direct handler check when ctx["error"] itself is serialized as string
            handler = app.exception_handlers[RequestValidationError]
            fake_req = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/v1/vault/secrets",
                    "headers": [],
                }
            )
            fake_exc = RequestValidationError(
                [
                    {
                        "type": "value_error",
                        "loc": ("body", "secret_value"),
                        "msg": f"Value error, Rejected raw secret: {secret_b}",
                        "input": secret_b,
                        "ctx": {"error": f"Rejected raw secret: {secret_b}"},
                    }
                ]
            )
            handled = await maybe_await(handler(fake_req, fake_exc))
            assert isinstance(handled, Response)
            handled_body = json.loads(bytes(handled.body).decode("utf-8"))
            assert secret_b not in json.dumps(handled_body)
            assert handled_body["detail"][0]["input"] == "[REDACTED]"
            assert (
                handled_body["detail"][0]["msg"]
                == "Value error, Rejected raw secret: [REDACTED]"
            )
            assert (
                handled_body["detail"][0]["ctx"]["error"]
                == "Rejected raw secret: [REDACTED]"
            )
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()


@pytest.mark.n1
async def test_resolve_draft_overwrites_stale_secret_id_and_skips_orphan_vault_secrets(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "draft_stale_idem.sqlite3")
    received: list[tuple[str, bytes]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def receive(request: Request) -> JSONResponse:
        body = await request.body()
        received.append((request.headers.get("x-controlbot-signature", ""), body))
        return JSONResponse({"ok": True})

    wh_transport = httpx.ASGITransport(app=wh_app)

    class _MockAsyncClient(httpx.AsyncClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("trust_env", None)
            kwargs["transport"] = wh_transport
            super().__init__(*args, **kwargs)

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            d = (
                await client.post(
                    "/api/v1/drafts",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "channel_type": "webhook",
                        "fields": {
                            "webhook_url": "http://mock-wh/hook",
                            "webhook_secret": "hmac-old",
                            "body": "Pump update",
                        },
                    },
                )
            ).json()
            old_id = d["fields"]["webhook_secret_id"]
            assert len(app.state.workspace_store.list_vault_secrets()) == 1

            # 1. action="update" with BOTH new webhook_secret AND stale webhook_secret_id
            u_resp = await client.post(
                f"/api/v1/drafts/{d['id']}/resolve",
                headers={"Idempotency-Key": "idem-upd-1"},
                json={
                    "action": "update",
                    "fields": {
                        "webhook_secret": "hmac-new-rotated",
                        "webhook_secret_id": old_id,
                    },
                },
            )
            assert u_resp.status_code == 200
            new_id = u_resp.json()["fields"]["webhook_secret_id"]
            assert new_id != old_id
            assert "hmac-new-rotated" not in u_resp.text
            assert len(app.state.workspace_store.list_vault_secrets()) == 2

            # 2. Duplicate Idempotency-Key -> 409 without creating an orphan Vault secret
            dup_resp = await client.post(
                f"/api/v1/drafts/{d['id']}/resolve",
                headers={"Idempotency-Key": "idem-upd-1"},
                json={
                    "action": "update",
                    "fields": {
                        "webhook_secret": "hmac-orphan-should-not-save",
                        "webhook_secret_id": new_id,
                    },
                },
            )
            assert dup_resp.status_code == 409
            assert len(app.state.workspace_store.list_vault_secrets()) == 2

            # 3. action="send" with BOTH new webhook_secret AND stale webhook_secret_id
            with patch("src.web.v1.runner.httpx.AsyncClient", _MockAsyncClient):
                s_resp = await client.post(
                    f"/api/v1/drafts/{d['id']}/resolve",
                    headers={"Idempotency-Key": "idem-send-1"},
                    json={
                        "action": "send",
                        "fields": {
                            "webhook_secret": "hmac-final-send",
                            "webhook_secret_id": old_id,
                        },
                    },
                )
            assert s_resp.status_code == 200
            send_id = s_resp.json()["fields"]["webhook_secret_id"]
            assert send_id not in {old_id, new_id}
            assert len(app.state.workspace_store.list_vault_secrets()) == 3
            assert len(received) == 1
            sig, raw_body = received[0]
            expected_sig = (
                "sha256="
                + hmac.new(b"hmac-final-send", raw_body, hashlib.sha256).hexdigest()
            )
            assert sig == expected_sig

            # 4. action="discard" does not create an orphan Vault secret
            d2 = (
                await client.post(
                    "/api/v1/drafts",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "channel_type": "webhook",
                        "fields": {"webhook_url": "http://mock-wh/hook", "body": "Discard"},
                    },
                )
            ).json()
            disc_resp = await client.post(
                f"/api/v1/drafts/{d2['id']}/resolve",
                json={
                    "action": "discard",
                    "fields": {"webhook_secret": "discard-orphan-secret"},
                },
            )
            assert disc_resp.status_code == 200
            assert disc_resp.json()["status"] == "discarded"
            assert len(app.state.workspace_store.list_vault_secrets()) == 3
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()
