"""Integration and unit tests for Milestone M1: Security, Auth, Vault & Isolation Hardening."""

from __future__ import annotations

import asyncio
import os
import signal
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from src.web.app import _render_studio_app_html, create_app
from src.web.auth import SlidingWindowRateLimiter, resolve_cors_config, resolve_web_token
from src.web.live_browser import LiveBrowserController, domain_matches_url, domains_compatible
from src.web.live_terminal import LiveTerminalSession
from src.web.v1.computer import ComputerGateway
from src.web.v1.store import WorkspaceStore
from src.web.workspace import (
    _is_sensitive_filename,
    build_agy_prompt_with_browser_context,
    stream_agy_prompt,
)

# ---------------------------------------------------------------------------
# 1. Server-Side Token Auth, CORS, Rate Limiting & /app Caching
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_token_auth_http_ws_and_dual_token_computer_ws(tmp_path: Path) -> None:
    secret = "m1-super-secret-token-42"
    app = create_app(db_path=tmp_path / "auth.sqlite3", web_token=secret)

    with TestClient(app) as client:
        # Protected HTTP endpoints reject missing/wrong token with 401 + WWW-Authenticate
        for path in (
            "/api/system/info",
            "/api/v1/bots",
            "/studio-legacy",
            "/",
            "/tasks/nonexistent",
        ):
            r_no = client.get(path)
            assert r_no.status_code == 401, f"{path} without token returned {r_no.status_code}"
            assert r_no.headers.get("www-authenticate") == "Bearer"

            r_bad = client.get(path, headers={"Authorization": "Bearer wrong-token"})
            assert r_bad.status_code == 401

        assert client.post("/api/v1/computers/default/vnc-token").status_code == 401
        assert client.post("/ui/tasks", data={"query": "x"}).status_code == 401

        # Mismatched query + Bearer header must NOT pass
        r_mixed = client.get(
            f"/api/v1/bots?token={secret}",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r_mixed.status_code == 401

        # Valid query token or Bearer header succeeds
        assert client.get(f"/api/v1/bots?token={secret}").status_code == 200
        assert (
            client.get(
                "/api/v1/bots",
                headers={"Authorization": f"Bearer {secret}"},
            ).status_code
            == 200
        )

        # Health, /app, /assets, and webhook routine route remain exempted from web token
        assert client.get("/health").status_code == 200
        assert client.get("/app").status_code == 200
        assert client.get("/app/chat").status_code == 200

        rtn = client.post(
            "/api/v1/bots/bot_chief/routines",
            headers={"Authorization": f"Bearer {secret}"},
            json={
                "name": "Webhook Routine",
                "instruction": "Ping",
                "schedule_type": "webhook",
            },
        ).json()
        # Webhook endpoint uses its own webhook_key, not web_token
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rtn['id']}",
                headers={"Authorization": "Bearer wrong-webhook-key"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rtn['id']}",
                headers={"Authorization": f"Bearer {rtn['webhook_key']}"},
            ).status_code
            == 202
        )

        # /ws/terminal and /ws/browser enforce web token before accept (close 4401)
        for ws_path in ("/ws/terminal", "/ws/browser"):
            with (
                pytest.raises(Exception) as exc_info,  # noqa: B017
                client.websocket_connect(ws_path),
            ):
                pass
            assert "4401" in str(exc_info.value) or getattr(exc_info.value, "code", None) == 4401

        with client.websocket_connect(f"/ws/terminal?token={secret}") as ws_term:
            ready = ws_term.receive_json()
            assert ready["type"] == "ready"

        # Mint cap_token via authenticated endpoint and test dual-token computer WS
        tok = client.post(
            "/api/v1/computers/default/vnc-token",
            headers={"Authorization": f"Bearer {secret}"},
        ).json()
        cap = tok["cap_token"]

        # Valid cap_token works without web token
        with client.websocket_connect(f"/ws/v1/computers/default/control?cap_token={cap}") as cws:
            st = cws.receive_json()
            assert st["op"] == "computer.state"

        # Valid web token works when cap_token is omitted
        with client.websocket_connect(
            f"/ws/v1/computers/default/control?token={secret}"
        ) as cws2:
            st2 = cws2.receive_json()
            assert st2["op"] == "computer.state"

        # Invalid cap_token is rejected even if web token is also supplied
        with (
            pytest.raises(Exception) as bad_cap_exc,  # noqa: B017
            client.websocket_connect(
                f"/ws/v1/computers/default/control?cap_token=bogus&token={secret}"
            ),
        ):
            pass
        assert (
            "4401" in str(bad_cap_exc.value)
            or getattr(bad_cap_exc.value, "code", None) == 4401
        )


@pytest.mark.n1
def test_resolve_web_token_env_and_cors_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROKBOT_WEB_TOKEN", raising=False)
    monkeypatch.delenv("CONTROLBOT_WEB_TOKEN", raising=False)
    assert resolve_web_token() is None

    monkeypatch.setenv("CONTROLBOT_WEB_TOKEN", "ctrl-tok")
    assert resolve_web_token() == "ctrl-tok"

    monkeypatch.setenv("GROKBOT_WEB_TOKEN", "grok-tok")
    assert resolve_web_token() == "grok-tok"
    assert resolve_web_token("explicit-tok") == "explicit-tok"

    # Wildcard CORS disables credentials
    wildcard_cfg = resolve_cors_config(["*"])
    assert wildcard_cfg.allow_origins == ["*"]
    assert wildcard_cfg.allow_credentials is False


@pytest.mark.n2
def test_cors_middleware_defaults_and_rate_limiting(tmp_path: Path) -> None:
    app = create_app(
        db_path=tmp_path / "cors_rl.sqlite3",
        rate_limits={
            "vnc_token": (2, 60.0),
            "attachments": (2, 60.0),
            "webhooks": (2, 60.0),
            "secure_fill": (2, 60.0),
            "messages": (2, 60.0),
        },
    )

    with TestClient(app) as client:
        # Loopback origin allowed with credentials
        preflight_ok = client.options(
            "/api/v1/bots",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert preflight_ok.status_code == 200
        assert preflight_ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
        assert preflight_ok.headers.get("access-control-allow-credentials") == "true"

        # Untrusted external origin rejected (no ACAO)
        preflight_evil = client.options(
            "/api/v1/bots",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in preflight_evil.headers

        # Rate limits across all 5 sensitive POST endpoints
        assert client.post("/api/v1/computers/default/vnc-token").status_code == 200
        assert client.post("/api/v1/computers/default/vnc-token").status_code == 200
        rl_vnc = client.post("/api/v1/computers/default/vnc-token")
        assert rl_vnc.status_code == 429
        assert int(rl_vnc.headers["retry-after"]) >= 1

        for _ in range(2):
            assert (
                client.post(
                    "/api/v1/attachments",
                    params={"filename": "a.txt"},
                    content=b"hi",
                ).status_code
                == 201
            )
        assert (
            client.post(
                "/api/v1/attachments",
                params={"filename": "a.txt"},
                content=b"hi",
            ).status_code
            == 429
        )

        for _ in range(2):
            assert (
                client.post(
                    "/api/v1/vault/secure-fill",
                    json={
                        "bot_id": "bot_chief",
                        "domain": "erp.local",
                        "values": {"password": "pw"},
                        "save_to_vault": True,
                    },
                ).status_code
                == 200
            )
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "erp.local",
                    "values": {"password": "pw"},
                    "save_to_vault": True,
                },
            ).status_code
            == 429
        )

        rtn = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={"name": "RL Hook", "instruction": "x", "schedule_type": "webhook"},
        ).json()
        for _ in range(2):
            assert (
                client.post(
                    f"/api/v1/webhooks/routines/{rtn['id']}",
                    headers={"Authorization": f"Bearer {rtn['webhook_key']}"},
                ).status_code
                == 202
            )
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rtn['id']}",
                headers={"Authorization": f"Bearer {rtn['webhook_key']}"},
            ).status_code
            == 429
        )

        for _ in range(2):
            assert (
                client.post(
                    "/api/v1/threads/thr_bot_chief/messages",
                    json={"content": "hello"},
                ).status_code
                == 202
            )
        assert (
            client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": "hello"},
            ).status_code
            == 429
        )


@pytest.mark.n1
def test_sliding_window_rate_limiter_clock_and_eviction() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(clock=lambda: now[0], max_keys=16)
    assert limiter.check("b", "k1", limit=2, window_seconds=10.0) == (True, 0)
    assert limiter.check("b", "k1", limit=2, window_seconds=10.0) == (True, 0)
    allowed, retry = limiter.check("b", "k1", limit=2, window_seconds=10.0)
    assert allowed is False
    assert retry == 10
    now[0] += 10.1
    assert limiter.check("b", "k1", limit=2, window_seconds=10.0) == (True, 0)

    for idx in range(30):
        limiter.check("b", f"evict-{idx}", limit=5, window_seconds=10.0)
    assert len(limiter._windows) <= 16


@pytest.mark.n2
def test_app_caching_importmap_fetch_wrapper_and_html_parser(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "cache.sqlite3")
    with TestClient(app) as client:
        resp = client.get("/app?token=secret-url-tok")
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"
        html_body = resp.text
        assert "secret-url-tok" not in html_body
        assert "importmap" in html_body
        assert "window.__GB_TOKEN" in html_body
        assert "window.fetch" in html_body
        assert "https://" not in html_body.lower()

        assets_dir = Path("frontend/dist/assets")
        js_files = sorted(assets_dir.glob("*.js"))
        assert js_files, "Expected built frontend JS bundle under frontend/dist/assets"
        asset_resp = client.get(f"/assets/{js_files[0].name}")
        assert asset_resp.status_code == 200
        assert asset_resp.headers.get("cache-control") == "public, max-age=31536000, immutable"

    # Attribute-order independence & modulepreload support in _render_studio_app_html
    sample = (
        '<!doctype html><html><head>'
        '<link href="/assets/style-1.css" rel="stylesheet">'
        '<link href="/assets/vendor-1.js" rel="modulepreload">'
        '<script src="/assets/main-1.js" type="module" crossorigin></script>'
        "</head><body><div id='root'></div></body></html>"
    )
    rendered = _render_studio_app_html(sample, tmp_path)
    assert '"/assets/style-1.css"' in rendered
    assert '"/assets/vendor-1.js"' in rendered
    assert '"/assets/main-1.js"' in rendered
    assert '<link href="/assets/style-1.css"' not in rendered
    assert '<script src="/assets/main-1.js"' not in rendered


# ---------------------------------------------------------------------------
# 2. vault/secure-fill Origin Match & Public LiveBrowserController API
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_domain_matching_and_compatibility_helpers() -> None:
    assert domain_matches_url("erp.local", "https://erp.local/login") is True
    assert domain_matches_url("erp.local", "https://app.erp.local/login") is True
    assert domain_matches_url("127.0.0.1:8080", "http://127.0.0.1:8080/auth") is True
    assert domain_matches_url("127.0.0.1", "http://127.0.0.1:8080/auth") is True

    # Fail-closed edge cases
    assert domain_matches_url("", "https://erp.local/login") is False
    assert domain_matches_url("erp.local", "") is False
    assert domain_matches_url("erp.local", "about:blank") is False
    assert domain_matches_url("erp.local", "file:///etc/passwd") is False
    assert domain_matches_url("erp.local", "https://myerp.local/login") is False
    assert domain_matches_url("erp.local", "https://evil.local/erp.local") is False
    assert domain_matches_url("127.0.0.1:8080", "http://127.0.0.1:9000/auth") is False
    assert domain_matches_url("https://erp.local", "http://erp.local/login") is False
    assert domain_matches_url("evil.com@erp.local", "https://erp.local/login") is False

    assert domains_compatible("erp.local", "sub.erp.local") is True
    assert domains_compatible("erp.local", "evil.local") is False


@pytest.mark.n1
async def test_live_browser_controller_public_api_fail_closed(tmp_path: Path) -> None:
    ctrl = LiveBrowserController(profile_root=tmp_path / "prof")
    assert ctrl.current_url() is None
    res = await ctrl.fill_credentials({"password": "x"}, expected_domain="erp.local")
    assert res["filled"] is False
    assert res["reason"] == "browser_not_running"
    assert res["url"] is None


@pytest.mark.n2
def test_vault_secure_fill_origin_check_ownership_cancel_and_compat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_html = (
        b"<!DOCTYPE html><html><head><title>ERP Login</title></head><body>"
        b"<form><input name='username' type='text'><input name='password' type='password'></form>"
        b"</body></html>"
    )

    class _LoginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(login_html)))
            self.end_headers()
            self.wfile.write(login_html)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    login_url = f"http://127.0.0.1:{port}/login"

    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles"))
    app = create_app(db_path=tmp_path / "vault_fill.sqlite3")
    try:
        with TestClient(app) as client:
            # 1. Create a second bot for cross-bot ownership test
            bot2 = client.post("/api/v1/bots", json={"name": "Finance Bot"}).json()

            # 2. Save secret owned by bot_chief for 127.0.0.1
            sec = client.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": "bot_chief",
                    "name": "Local ERP",
                    "domain": f"127.0.0.1:{port}",
                    "username": "alice",
                    "value": "TopSecretPW!",
                },
            ).json()

            # 3. Compatibility: form_id=None + save_to_vault=True + stopped browser -> 200
            compat = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "erp.local",
                    "fields": {"username": "u", "password": "p"},
                    "save_to_vault": True,
                },
            )
            assert compat.status_code == 200
            assert compat.json()["filled"] is False
            assert "never shown" in compat.json()["message"].lower()

            # 4. Secure form with stopped browser -> 409 and form stays pending
            form = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "domain": f"127.0.0.1:{port}",
                    "title": "ERP Login",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                },
            ).json()
            stopped_fail = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": form["id"],
                    "bot_id": "bot_chief",
                    "domain": f"127.0.0.1:{port}",
                    "secret_id": sec["id"],
                },
            )
            assert stopped_fail.status_code == 409
            assert app.state.workspace_store.get_secure_form(form["id"])["status"] == "pending"

            # 5. Cross-bot secret_id rejected with 403
            form_bot2 = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": bot2["id"],
                    "thread_id": bot2["thread_id"],
                    "domain": f"127.0.0.1:{port}",
                    "title": "Bot2 Form",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            assert (
                client.post(
                    "/api/v1/vault/secure-fill",
                    json={
                        "form_id": form_bot2["id"],
                        "bot_id": bot2["id"],
                        "domain": f"127.0.0.1:{port}",
                        "secret_id": sec["id"],
                    },
                ).status_code
                == 403
            )

            # 6. Cancel action marks form cancelled
            cancel_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": form_bot2["id"], "action": "cancel"},
            )
            assert cancel_resp.status_code == 200
            assert cancel_resp.json()["status"] == "cancelled"
            assert (
                app.state.workspace_store.get_secure_form(form_bot2["id"])["status"]
                == "cancelled"
            )

            # 7. Navigate live browser to local login page and test mismatch vs match
            nav = client.post("/api/browser/action", json={"type": "navigate", "url": login_url})
            assert nav.status_code == 200

            evil_form = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "domain": "erp.local",
                    "title": "Mismatch Form",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            mismatch_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": evil_form["id"],
                    "bot_id": "bot_chief",
                    "domain": "erp.local",
                    "values": {"username": "bob", "password": "SecretValue"},
                },
            )
            assert mismatch_resp.status_code == 409
            assert (
                app.state.workspace_store.get_secure_form(evil_form["id"])["status"] == "pending"
            )

            # Matching domain succeeds and marks form submitted
            ok_fill = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": form["id"],
                    "bot_id": "bot_chief",
                    "domain": f"127.0.0.1:{port}",
                    "secret_id": sec["id"],
                },
            )
            assert ok_fill.status_code == 200
            assert ok_fill.json()["filled"] is True
            assert (
                app.state.workspace_store.get_secure_form(form["id"])["status"] == "submitted"
            )
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# 3. Attachment Stored XSS, Upload Streaming & Route Fixes
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_attachments_streaming_limit_xss_pages_reactions_and_artifact_delete(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "routes.sqlite3")
    uploads_dir = tmp_path / "uploads"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        # 1. Streaming upload > 25 MiB aborts with 413 without leaving a file on disk
        async def _oversized_stream() -> Any:
            chunk = b"A" * (1024 * 1024)
            for _ in range(26):
                yield chunk

        oversized = await client.post(
            "/api/v1/attachments",
            params={"filename": "huge.bin"},
            content=_oversized_stream(),
        )
        assert oversized.status_code == 413
        assert not list(uploads_dir.glob("*"))

        # 2. Active XSS MIME/ext types get sandbox CSP, nosniff, and attachment disposition
        for fname, ctype, body in (
            ("xss.html", "text/html", b"<script>alert(1)</script>"),
            ("vec.svg", "image/svg+xml", b"<svg onload=alert(1)></svg>"),
            ("evil.js", "application/javascript", b"alert(1)"),
        ):
            up = await client.post(
                "/api/v1/attachments",
                params={"filename": fname, "thread_id": "thr_bot_chief"},
                headers={"Content-Type": ctype},
                content=body,
            )
            assert up.status_code == 201
            att_id = up.json()["id"]
            dl = await client.get(f"/api/v1/attachments/{att_id}")
            assert dl.status_code == 200
            assert dl.headers.get("x-content-type-options") == "nosniff"
            assert dl.headers.get("content-security-policy") == "sandbox; default-src 'none'"
            assert dl.headers.get("content-disposition", "").startswith("attachment;")

        # 3. Group Channel New Page fallback when bot_id is omitted/empty
        bot2_resp = await client.post("/api/v1/bots", json={"name": "Ops Helper"})
        assert bot2_resp.status_code == 201
        bot2_id = bot2_resp.json()["id"]
        chn_resp = await client.post(
            "/api/v1/channels",
            json={"name": "Ops Room", "bot_ids": ["bot_chief", bot2_id]},
        )
        assert chn_resp.status_code == 201
        chn = chn_resp.json()
        page_resp = await client.post(
            "/api/v1/pages",
            json={
                "bot_id": "",
                "channel_id": chn["id"],
                "title": "Group Runbook",
                "content_md": "# Runbook\nStep 1",
            },
        )
        assert page_resp.status_code == 201
        assert page_resp.json()["bot_id"] == "bot_chief"
        assert page_resp.json()["thread_id"] == chn["thread_id"]

        # 4. Reaction emits SSE event & DELETE /artifacts/{id} cleans disk + emits SSE
        bus = app.state.event_bus
        marker = bus.publish("test.marker", {"ok": True})
        msg = app.state.workspace_store.create_message(
            thread_id="thr_bot_chief",
            sender_type="bot",
            sender_bot_id="bot_chief",
            sender_name="Chief",
            content="Check this",
            status="done",
        )
        rx = await client.post(
            f"/api/v1/messages/{msg['id']}/reactions",
            json={"emoji": "👍", "action": "add"},
        )
        assert rx.status_code == 200

        # Upload a file (auto-creates artifact), delete artifact -> unlinks file + emits SSE
        up_file = (
            await client.post(
                "/api/v1/attachments",
                params={"filename": "cleanup_me.txt", "thread_id": "thr_bot_chief"},
                content=b"temp content",
            )
        ).json()
        disk_files = list(uploads_dir.glob(f"{up_file['id']}_*"))
        assert len(disk_files) == 1
        lib = (await client.get("/api/v1/bots/bot_chief/library")).json()["items"]
        target_art = next(a for a in lib if a["url"] == f"/api/v1/attachments/{up_file['id']}")

        del_resp = await client.delete(f"/api/v1/artifacts/{target_art['id']}")
        assert del_resp.status_code == 200
        assert not disk_files[0].exists()

        sub = bus.subscribe(last_event_id=marker["id"])
        replay_types: list[str] = []
        try:
            for _ in range(2):
                ev = await asyncio.wait_for(anext(sub), timeout=2.0)
                replay_types.append(str(ev["type"]))
        finally:
            await sub.aclose()
        assert "message.reaction" in replay_types
        assert "artifact.deleted" in replay_types


# ---------------------------------------------------------------------------
# 4. Takeover Lock Enforcement & ComputerGateway State
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_takeover_lock_enforcement_legacy_and_force_interactive_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles"))
    app = create_app(db_path=tmp_path / "takeover.sqlite3")

    with TestClient(app) as client:
        tok = client.post("/api/v1/computers/default/vnc-token").json()

        # ws_computer_screencast rejects force_interactive=true when not human_takeover
        with client.websocket_connect(tok["ws_screencast_url"]) as sc_ws:
            init_st = sc_ws.receive_json()
            assert init_st["type"] == "status"
            sc_ws.send_json(
                {"type": "click", "x": 10, "y": 10, "force_interactive": True}
            )
            blocked = sc_ws.receive_json()
            assert blocked["type"] == "blocked"

        # Take over control
        assert (
            client.post("/api/v1/computers/default/takeover", json={"owner": "op"}).status_code
            == 200
        )

        # Legacy POST /api/browser/action returns 423 Locked during human takeover
        locked = client.post("/api/browser/action", json={"type": "navigate", "url": "127.0.0.1"})
        assert locked.status_code == 423

        # Start/Stop remain accessible for interactive operator toolbar
        assert client.post("/api/browser/start", json={}).status_code == 200
        assert client.post("/api/browser/stop").status_code == 200

        # WS /ws/browser rejects connection with 4423 during human takeover
        with (
            pytest.raises(Exception) as ws_exc,  # noqa: B017
            client.websocket_connect("/ws/browser"),
        ):
            pass
        assert "4423" in str(ws_exc.value) or getattr(ws_exc.value, "code", None) == 4423

        # Handback unlocks /api/browser/action and /ws/browser
        assert client.post("/api/v1/computers/default/handback", json={}).status_code == 200
        assert client.post("/api/browser/stop").status_code == 200

        # Mid-session takeover closes /ws/browser with 4423 before executing mutating command
        with client.websocket_connect("/ws/browser") as bws:
            assert bws.receive_json()["type"] == "status"
            assert (
                client.post(
                    "/api/v1/computers/default/takeover", json={"owner": "op"}
                ).status_code
                == 200
            )
            bws.send_json({"type": "reload"})
            err_msg = bws.receive_json()
            assert err_msg["type"] == "error"


@pytest.mark.n1
def test_cap_secret_0600_persistence_and_optional_store_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GROKBOT_CAP_SECRET", raising=False)
    gw1 = ComputerGateway(state_dir=tmp_path)
    secret_file = tmp_path / ".grokbot_cap_secret"
    assert secret_file.is_file()
    mode = stat.S_IMODE(secret_file.stat().st_mode)
    assert mode == 0o600

    cap = gw1.mint_cap_token("default")
    gw2 = ComputerGateway(state_dir=tmp_path)
    assert gw2.verify_cap_token("default", cap) is True

    # Optional hasattr-guarded store persistence hooks
    class _MockVmStore:
        def __init__(self) -> None:
            self.vms: dict[str, dict[str, Any]] = {}
            self.steps: dict[str, list[dict[str, Any]]] = {}

        def get_computer_vm(self, vm_id: str) -> dict[str, Any] | None:
            return self.vms.get(vm_id)

        def upsert_computer_vm(self, vm_id: str, data: dict[str, Any]) -> None:
            self.vms[vm_id] = dict(data)

        def list_teach_steps(self, vm_id: str) -> list[dict[str, Any]]:
            return list(self.steps.get(vm_id, []))

        def append_teach_step(self, vm_id: str, step: dict[str, Any]) -> None:
            self.steps.setdefault(vm_id, []).append(dict(step))

        def clear_teach_steps(self, vm_id: str) -> None:
            self.steps[vm_id] = []

    mock_store = _MockVmStore()
    gw_a = ComputerGateway(state_dir=tmp_path, store=mock_store)
    gw_a.takeover("default", owner="alice")
    gw_a.start_teach("default", name="Persisted Flow", bot_id="bot_chief", thread_id="thr_1")
    gw_a.record_teach_step("default", action="click", description="Click button", url="http://x")

    gw_b = ComputerGateway(state_dir=tmp_path, store=mock_store)
    assert gw_b.is_human_takeover("default") is True
    assert gw_b.is_teaching("default") is True
    name, bot_id, thread_id, steps = gw_b.stop_teach("default")
    assert name == "Persisted Flow"
    assert bot_id == "bot_chief"
    assert thread_id == "thr_1"
    assert len(steps) == 1


# ---------------------------------------------------------------------------
# 5. File Explorer Symlink Fix & Workspace Hardening
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_symlink_delete_safety_and_sensitive_filenames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "DemoProj"
    proj.mkdir(parents=True)
    outside_dir = tmp_path / "Outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret_outside.txt"
    outside_file.write_text("DO NOT DELETE", encoding="utf-8")

    real_file = proj / "real.txt"
    real_file.write_text("keep me", encoding="utf-8")
    real_sub = proj / "subdir"
    real_sub.mkdir()
    (real_sub / "nested.txt").write_text("keep dir", encoding="utf-8")

    file_link = proj / "file_link.txt"
    file_link.symlink_to(real_file)
    dir_link = proj / "dir_link"
    dir_link.symlink_to(real_sub)
    broken_link = proj / "broken_link.txt"
    broken_link.symlink_to(proj / "does_not_exist.txt")
    escape_link = proj / "escape_link.txt"
    escape_link.symlink_to(outside_file)
    dir_escape = proj / "dir_escape"
    dir_escape.symlink_to(outside_dir)

    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))
    app = create_app(db_path=tmp_path / "files.sqlite3")

    with TestClient(app) as client:
        # Unlink in-project file symlink -> symlink removed, target preserved
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "file_link.txt"},
            ).status_code
            == 200
        )
        assert not file_link.exists() and not file_link.is_symlink()
        assert real_file.read_text(encoding="utf-8") == "keep me"

        # Unlink in-project dir symlink -> symlink removed, target directory preserved
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "dir_link"},
            ).status_code
            == 200
        )
        assert not dir_link.exists() and not dir_link.is_symlink()
        assert (real_sub / "nested.txt").read_text(encoding="utf-8") == "keep dir"

        # Unlink broken in-project symlink -> removed cleanly
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "broken_link.txt"},
            ).status_code
            == 200
        )
        assert not broken_link.is_symlink()

        # Escaping symlink & traversal via symlinked parent dir -> 403, outside file untouched
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "escape_link.txt"},
            ).status_code
            == 403
        )
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "dir_escape/secret_outside.txt"},
            ).status_code
            == 403
        )
        assert outside_file.read_text(encoding="utf-8") == "DO NOT DELETE"

        # Sensitive filenames blocked across read/download/write/upload/delete
        sensitive_paths = [
            "app.sqlite3",
            "state.db",
            "authorized_keys",
            ".ssh/config",
            ".aws/config",
            ".pypirc",
            "id_ecdsa",
            "AuthKey.p8",
            "keystore.jks",
            "vpn.ovpn",
        ]
        for rel in sensitive_paths:
            assert _is_sensitive_filename(Path(rel)) is True
            full_s = proj / rel
            full_s.parent.mkdir(parents=True, exist_ok=True)
            full_s.write_text("sensitive", encoding="utf-8")
            assert (
                client.get(
                    "/api/v1/computers/default/file",
                    params={"project": "DemoProj", "path": rel},
                ).status_code
                == 403
            )
            assert (
                client.get(
                    "/api/v1/computers/default/file/download",
                    params={"project": "DemoProj", "path": rel},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/computers/default/files/write",
                    json={"project": "DemoProj", "path": rel, "content": "x"},
                ).status_code
                == 403
            )
            assert (
                client.delete(
                    "/api/v1/computers/default/files",
                    params={"project": "DemoProj", "path": rel},
                ).status_code
                == 403
            )
        assert _is_sensitive_filename(Path("src/config.py")) is False


@pytest.mark.n1
async def test_agy_prompt_base_url_and_stream_stderr_no_deadlock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = {"running": True, "url": "http://127.0.0.1:9999", "title": "T", "visible_text": "hi"}
    explicit = build_agy_prompt_with_browser_context(
        "click", ctx, base_url="http://127.0.0.1:9123/"
    )
    assert "http://127.0.0.1:9123/api/browser/action" in explicit

    monkeypatch.setenv("CONTROLBOT_BASE_URL", "http://127.0.0.1:8765")
    env_prompt = build_agy_prompt_with_browser_context("click", ctx)
    assert "http://127.0.0.1:8765/api/browser/action" in env_prompt

    # Child script writes >128 KiB to stderr BEFORE writing NDJSON to stdout
    fake_agy = tmp_path / "fake_agy.py"
    fake_agy.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "sys.stderr.write('E' * (192 * 1024))\n"
        "sys.stderr.flush()\n"
        "print(json.dumps({'event': 'result', 'conversation_id': 'c1', "
        "'result': {'status': 'SUCCESS', 'response': 'ok', 'conversation_id': 'c1'}}))\n",
        encoding="utf-8",
    )
    fake_agy.chmod(0o755)
    monkeypatch.setattr("src.web.workspace.find_agy_executable", lambda: str(fake_agy))

    events: list[dict[str, Any]] = []
    async for ev in stream_agy_prompt(prompt="test stderr", timeout_s=10.0):
        events.append(ev)
    assert any(ev.get("type") == "done" and ev.get("response") == "ok" for ev in events)


# ---------------------------------------------------------------------------
# 6. LiveTerminalSession Reliability
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_live_terminal_blocking_write_split_utf8_popen_fail_and_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Popen failure does not leak master_fd
    before_fds = set(os.listdir("/proc/self/fd"))

    def _boom_popen(*args: Any, **kwargs: Any) -> Any:
        raise OSError("boom")

    monkeypatch.setattr(subprocess, "Popen", _boom_popen)
    with pytest.raises(OSError, match="boom"):
        LiveTerminalSession(cwd=tmp_path)
    monkeypatch.undo()
    after_fds = set(os.listdir("/proc/self/fd"))
    assert after_fds == before_fds

    # 2. Split multi-byte UTF-8 across _on_readable calls
    term = LiveTerminalSession(cwd=tmp_path)
    try:
        rocket = "🚀ñ".encode()
        part1, part2 = rocket[:2], rocket[2:]
        reads: list[bytes | BaseException] = [part1, BlockingIOError(), part2, BlockingIOError()]
        reads_iter = iter(reads)

        def _fake_read(fd: int, n: int) -> bytes:
            del fd, n
            nxt = next(reads_iter)
            if isinstance(nxt, BaseException):
                raise nxt
            return nxt

        monkeypatch.setattr(os, "read", _fake_read)
        term._on_readable()
        term._on_readable()
        monkeypatch.undo()

        collected = ""
        while not term.output_queue.empty():
            item = term.output_queue.get_nowait()
            if item:
                collected += item
        assert "🚀ñ" in collected
    finally:
        term.close()

    # 3. BlockingIOError during write() buffers and flushes in order without dropping bytes
    term2 = LiveTerminalSession(cwd=tmp_path)
    try:
        orig_write = os.write
        block_once = [True]

        def _partial_then_block(fd: int, data: Any) -> int:
            if fd == term2._master_fd and block_once[0]:
                block_once[0] = False
                raise BlockingIOError(11, "EAGAIN")
            return orig_write(fd, data)

        monkeypatch.setattr(os, "write", _partial_then_block)
        term2.write("echo TERM_BUF_1\n")
        assert len(term2._write_buffer) > 0
        assert term2._writer_attached is True
        monkeypatch.undo()

        # Append second line while buffer still draining
        term2.write("echo TERM_BUF_2\n")
        deadline = asyncio.get_running_loop().time() + 5.0
        out = ""
        while asyncio.get_running_loop().time() < deadline:
            try:
                chunk = await asyncio.wait_for(term2.output_queue.get(), timeout=0.5)
            except TimeoutError:
                continue
            if chunk is None:
                break
            out += chunk
            if "TERM_BUF_1" in out and "TERM_BUF_2" in out:
                break
        assert "TERM_BUF_1" in out
        assert "TERM_BUF_2" in out

        # 4. send_signal(SIGINT) interrupts sleeping child cleanly
        term2.write("sleep 30\n")
        await asyncio.sleep(0.15)
        assert term2.send_signal(signal.SIGINT) is True
        term2.write("echo AFTER_SIGINT\n")
        deadline2 = asyncio.get_running_loop().time() + 5.0
        out2 = ""
        while asyncio.get_running_loop().time() < deadline2:
            try:
                chunk = await asyncio.wait_for(term2.output_queue.get(), timeout=0.5)
            except TimeoutError:
                continue
            if chunk is None:
                break
            out2 += chunk
            if "AFTER_SIGINT" in out2:
                break
        assert "AFTER_SIGINT" in out2
    finally:
        term2.close()


# ---------------------------------------------------------------------------
# 7. Iteration 2 Security & Compatibility Regression Tests
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_domain_matches_url_rejects_userinfo_backslash_and_control_chars() -> None:
    assert domain_matches_url("erp.local", "https://evil.com\\@erp.local/login") is False
    assert domain_matches_url("erp.local", "https://user:pass@erp.local/login") is False
    assert domain_matches_url("erp.local", "https://evil.com@erp.local/login") is False
    assert domain_matches_url("erp.local", "https://@erp.local/login") is False
    assert domain_matches_url("erp.local", "https://evil.com\\erp.local/login") is False
    assert domain_matches_url("erp.local", "https://erp.local\t/login") is False
    assert domain_matches_url("erp.local", "https://evil.com\n@erp.local/login") is False
    assert domain_matches_url("erp.local", "https://erp\x00.local/login") is False
    assert domain_matches_url("evil.com\\erp.local", "https://erp.local/login") is False
    assert domains_compatible("evil.com\\erp.local", "erp.local") is False
    # Valid URL with query space / @ in query remains unaffected
    assert domain_matches_url("erp.local", "https://erp.local/login?next=a@b") is True


@pytest.mark.n2
def test_vault_secure_fill_prevents_secret_origin_downgrade_and_requires_bot_ownership(
    tmp_path: Path,
) -> None:
    class _FakeLocator:
        def __init__(self, fills: list[tuple[str, str]], selector: str) -> None:
            self._fills = fills
            self._selector = selector

        @property
        def first(self) -> _FakeLocator:
            return self

        async def count(self) -> int:
            return 1

        async def fill(self, value: str, timeout: int = 2000) -> None:
            del timeout
            self._fills.append((self._selector, value))

    class _FakePage:
        def __init__(self, url: str) -> None:
            self.url = url
            self.fills: list[tuple[str, str]] = []

        def is_closed(self) -> bool:
            return False

        def locator(self, selector: str) -> _FakeLocator:
            return _FakeLocator(self.fills, selector)

    app = create_app(db_path=tmp_path / "vault_downgrade.sqlite3")
    with TestClient(app) as client:
        secret = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "Strict ERP Secret",
                "domain": "https://app.erp.local:8443",
                "username": "alice",
                "value": "StrictSecretPW!",
            },
        ).json()

        broad_form = client.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "domain": "erp.local",
                "title": "Broad ERP Form",
                "fields": [
                    {"name": "username", "label": "Username", "secret": False},
                    {"name": "password", "label": "Password", "secret": True},
                ],
            },
        ).json()

        # Attach fake running page at downgraded origin http://evil-sub.erp.local:80/phish
        fake_page = _FakePage("http://evil-sub.erp.local:80/phish")
        browser: LiveBrowserController = app.state.live_browser
        browser._context = object()  # type: ignore[assignment]
        browser._page = fake_page  # type: ignore[assignment]
        try:
            # 1. Secret bound to https://app.erp.local:8443 + broad form erp.local -> 409, no fill
            downgrade_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": broad_form["id"],
                    "secret_id": secret["id"],
                },
            )
            assert downgrade_resp.status_code == 409
            assert fake_page.fills == []
            assert (
                app.state.workspace_store.get_secure_form(broad_form["id"])["status"] == "pending"
            )

            # 2. Bot-owned secret_id with BOTH form_id=None and bot_id=None -> 403
            unscoped_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "secret_id": secret["id"],
                    "domain": "https://app.erp.local:8443",
                },
            )
            assert unscoped_resp.status_code == 403
            assert fake_page.fills == []

            empty_bot_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "secret_id": secret["id"],
                    "bot_id": "",
                    "domain": "https://app.erp.local:8443",
                },
            )
            assert empty_bot_resp.status_code == 403
            assert fake_page.fills == []

            # 3. Matching origin https://app.erp.local:8443/login succeeds and marks form submitted
            fake_page.url = "https://app.erp.local:8443/login"
            ok_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": broad_form["id"],
                    "secret_id": secret["id"],
                },
            )
            assert ok_resp.status_code == 200
            assert ok_resp.json()["filled"] is True
            assert len(fake_page.fills) == 2
            assert (
                app.state.workspace_store.get_secure_form(broad_form["id"])["status"]
                == "submitted"
            )
        finally:
            browser._context = None
            browser._page = None


@pytest.mark.n2
def test_legacy_js_mime_attachment_and_file_read_symlink_escape_403(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "DemoProj"
    proj.mkdir(parents=True)
    outside_dir = tmp_path / "Outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "outside.txt"
    outside_file.write_text("outside secret", encoding="utf-8")
    (proj / "escape_file.txt").symlink_to(outside_file)
    (proj / "escape_dir").symlink_to(outside_dir)
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))

    app = create_app(db_path=tmp_path / "mime_symlink.sqlite3")
    with TestClient(app) as client:
        for mime in ("application/x-javascript", "application/x-ecmascript"):
            up = client.post(
                "/api/v1/attachments",
                params={"filename": "code.txt"},
                headers={"Content-Type": mime},
                content=b"alert(1)",
            )
            assert up.status_code == 201
            att_id = up.json()["id"]
            dl = client.get(f"/api/v1/attachments/{att_id}")
            assert dl.status_code == 200
            assert dl.headers.get("content-disposition", "").startswith("attachment;")
            assert dl.headers.get("x-content-type-options") == "nosniff"
            assert dl.headers.get("content-security-policy") == "sandbox; default-src 'none'"

        # Symlink escape on GET /api/v1/computers/{vm_id}/file returns 403 Forbidden
        for bad_rel in ("escape_file.txt", "escape_dir/outside.txt"):
            resp = client.get(
                "/api/v1/computers/default/file",
                params={"project": "DemoProj", "path": bad_rel},
            )
            assert resp.status_code == 403


@pytest.mark.n2
def test_computer_gateway_save_teach_steps_persistence_with_workspace_store(
    tmp_path: Path,
) -> None:
    store = WorkspaceStore(tmp_path / "teach_persist.sqlite3")
    gw1 = ComputerGateway(state_dir=tmp_path, store=store)
    gw1.start_teach("default", name="M2 Persisted Flow", bot_id="bot_chief", thread_id="thr_1")
    gw1.record_teach_step("default", action="click", description="Step 1", url="http://localhost")
    gw1.record_teach_step("default", action="type", description="Step 2", url="http://localhost")

    persisted_steps = store.get_teach_steps("default")
    assert len(persisted_steps) == 2
    assert persisted_steps[0]["description"] == "Step 1"
    assert persisted_steps[1]["description"] == "Step 2"

    # Reload ComputerGateway from SQLite WorkspaceStore
    gw2 = ComputerGateway(state_dir=tmp_path, store=store)
    assert gw2.is_teaching("default") is True
    name, bot_id, thread_id, steps = gw2.stop_teach("default")
    assert name == "M2 Persisted Flow"
    assert bot_id == "bot_chief"
    assert thread_id == "thr_1"
    assert len(steps) == 2
    assert store.get_teach_steps("default") == []


# ---------------------------------------------------------------------------
# 8. Iteration 3 Fail-Closed Domainless Fill Regression Tests
# ---------------------------------------------------------------------------


@pytest.mark.n1
async def test_fill_credentials_fails_closed_without_expected_domain(tmp_path: Path) -> None:
    class _FakeLocator:
        def __init__(
            self,
            fills: list[tuple[str, str]],
            clicks: list[str],
            selector: str,
        ) -> None:
            self._fills = fills
            self._clicks = clicks
            self._selector = selector

        @property
        def first(self) -> _FakeLocator:
            return self

        async def count(self) -> int:
            return 1

        async def fill(self, value: str, timeout: int = 2000) -> None:
            del timeout
            self._fills.append((self._selector, value))

        async def click(self, timeout: int = 2000) -> None:
            del timeout
            self._clicks.append(self._selector)

    class _FakePage:
        def __init__(self, url: str) -> None:
            self.url = url
            self.fills: list[tuple[str, str]] = []
            self.clicks: list[str] = []

        def is_closed(self) -> bool:
            return False

        def locator(self, selector: str) -> _FakeLocator:
            return _FakeLocator(self.fills, self.clicks, selector)

    browser = LiveBrowserController(profile_root=tmp_path / "prof_domain_req")
    fake_page = _FakePage("http://evil.com/phish")
    browser._context = object()  # type: ignore[assignment]
    browser._page = fake_page  # type: ignore[assignment]
    try:
        for empty_domain in (None, "", "   \t", [], ["", "  "]):
            res = await browser.fill_credentials(
                {"username": "alice", "password": "x"},
                expected_domain=empty_domain,
                submit_selector="button[type='submit']",
            )
            assert res == {
                "filled": False,
                "reason": "domain_required",
                "url": "http://evil.com/phish",
            }
            assert fake_page.fills == []
            assert fake_page.clicks == []

        # Positive control: explicit matching domain succeeds
        ok_res = await browser.fill_credentials(
            {"password": "x"},
            expected_domain="evil.com",
            submit_selector="button[type='submit']",
        )
        assert ok_res["filled"] is True
        assert ok_res["reason"] == "ok"
        assert len(fake_page.fills) == 1
        assert fake_page.clicks == ["button[type='submit']"]
    finally:
        browser._context = None
        browser._page = None


@pytest.mark.n2
def test_vault_secure_fill_domainless_save_to_vault_never_fills_running_browser(
    tmp_path: Path,
) -> None:
    class _FakeLocator:
        def __init__(self, fills: list[tuple[str, str]], selector: str) -> None:
            self._fills = fills
            self._selector = selector

        @property
        def first(self) -> _FakeLocator:
            return self

        async def count(self) -> int:
            return 1

        async def fill(self, value: str, timeout: int = 2000) -> None:
            del timeout
            self._fills.append((self._selector, value))

    class _FakePage:
        def __init__(self, url: str) -> None:
            self.url = url
            self.fills: list[tuple[str, str]] = []

        def is_closed(self) -> bool:
            return False

        def locator(self, selector: str) -> _FakeLocator:
            return _FakeLocator(self.fills, selector)

    app = create_app(db_path=tmp_path / "vault_domainless.sqlite3")
    with TestClient(app) as client:
        domainless_secret = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "Domainless Secret",
                "domain": "",
                "username": "alice",
                "value": "DomainlessPW123!",
            },
        ).json()

        fake_page = _FakePage("http://evil.com/phish")
        browser: LiveBrowserController = app.state.live_browser
        browser._context = object()  # type: ignore[assignment]
        browser._page = fake_page  # type: ignore[assignment]
        try:
            # 1. Inline values + save_to_vault=True + domain="" -> saves to Vault only, 0 fills
            inline_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "",
                    "values": {"username": "alice", "password": "MySecretPassword!"},
                    "save_to_vault": True,
                },
            )
            assert inline_resp.status_code == 200
            inline_body = inline_resp.json()
            assert inline_body["filled"] is False
            assert inline_body["saved_secret_id"]
            assert "never shown" in inline_body["message"].lower()
            assert "no target domain" in inline_body["message"].lower()
            assert "MySecretPassword!" not in inline_resp.text
            assert fake_page.fills == []

            # 2. Domainless secret_id + save_to_vault=True + domain="" -> 409, 0 fills
            secret_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "",
                    "secret_id": domainless_secret["id"],
                    "save_to_vault": True,
                },
            )
            assert secret_resp.status_code == 409
            assert fake_page.fills == []

            # 3. Mismatched domain + save_to_vault=True -> 409, 0 fills
            mismatch_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "erp.local",
                    "values": {"username": "alice", "password": "MySecretPassword!"},
                    "save_to_vault": True,
                },
            )
            assert mismatch_resp.status_code == 409
            assert fake_page.fills == []

            # 4. Positive control: matching domain + save_to_vault=True fills and saves
            ok_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "evil.com",
                    "values": {"username": "alice", "password": "MySecretPassword!"},
                    "save_to_vault": True,
                },
            )
            assert ok_resp.status_code == 200
            assert ok_resp.json()["filled"] is True
            assert ok_resp.json()["saved_secret_id"]
            assert len(fake_page.fills) == 2
        finally:
            browser._context = None
            browser._page = None


