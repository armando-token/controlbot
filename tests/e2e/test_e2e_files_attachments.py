"""Opaque-box Tier 1 & Tier 2 E2E tests for Attachments, Stored XSS, Limits & Workspace Files."""

from __future__ import annotations

import asyncio
import gc
import json
import socket
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from tests.e2e._helpers import (
    IsolatedServer,
    trigger_and_wait_turn,
    wait_for_sse_event,
)

pytestmark = pytest.mark.e2e

_MIB = 1024 * 1024
_MAX_ATTACHMENT_BYTES = 25 * _MIB
_MAX_WORKSPACE_FILE_BYTES = 50 * _MIB

# Minimal valid 1x1 PNG bytes
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00"
    b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _iter_fixed_bytes(total_bytes: int, chunk_size: int = _MIB) -> Iterator[bytes]:
    """Stream `total_bytes` without allocating `total_bytes` in RAM."""
    full_chunk = b"A" * chunk_size
    remaining = total_bytes
    while remaining >= chunk_size:
        yield full_chunk
        remaining -= chunk_size
    if remaining > 0:
        yield b"A" * remaining


def _iter_json_write_payload(
    rel_path: str,
    content_bytes: int,
    chunk_size: int = _MIB,
) -> Iterator[bytes]:
    """Stream `{"path": ..., "content": "AAAA..."}` without allocating full payload in RAM."""
    yield f'{{"path": {json.dumps(rel_path)}, "content": "'.encode()
    yield from _iter_fixed_bytes(content_bytes, chunk_size=chunk_size)
    yield b'"}'


def _send_raw_oversized_content_length(
    host: str,
    port: int,
    path: str,
    content_length: int,
) -> tuple[int, bytes]:
    """Send an HTTP/1.1 POST header with an oversized Content-Length over raw loopback TCP."""
    req_head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((host, port), timeout=10.0) as sock:
        sock.settimeout(10.0)
        sock.sendall(req_head)
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except TimeoutError:
                break
            if not data:
                break
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                # Read any immediate JSON body after headers
                sock.settimeout(0.3)
    raw = b"".join(chunks)
    status_line = raw.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    return status_code, raw


def _assert_xss_hardened_headers(
    resp: httpx.Response,
    *,
    expected_disposition: str,
    expected_filename: str,
    expected_mime: str,
) -> None:
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("content-security-policy") == "sandbox; default-src 'none'"
    assert (
        resp.headers.get("content-disposition")
        == f'{expected_disposition}; filename="{expected_filename}"'
    )
    actual_mime = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    assert actual_mime == expected_mime.lower()


# ==============================================================================
# Tier 1 Tests (10 tests)
# ==============================================================================


def test_t1_attachment_raw_upload_and_exact_byte_roundtrip(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Raw attachment uploads for text/PNG/JSON/audio/bin round-trip exact bytes."""
    uploads_dir = server.tmp_dir / "uploads"
    samples: list[tuple[str, str, bytes]] = [
        ("notes.txt", "text/plain", b"hello controlbot\nline2\n"),
        ("pixel.png", "image/png", _TINY_PNG),
        ("data.json", "application/json", json.dumps({"ok": True, "n": 42}).encode("utf-8")),
        ("tone.mp3", "audio/mpeg", b"ID3\x03\x00\x00\x00\x00\x00\x00\xff\xfb\x90\x00"),
        ("blob.bin", "application/octet-stream", bytes(range(256))),
    ]

    with server.client() as client:
        for fname, mime, payload in samples:
            resp = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert resp.status_code == 201, f"{fname} failed: {resp.text}"
            meta = resp.json()
            att_id = str(meta["id"])
            assert meta["filename"] == fname
            assert meta["mime_type"] == mime
            assert meta["size_bytes"] == len(payload)

            disk_file = uploads_dir / f"{att_id}_{fname}"
            assert disk_file.is_file()
            assert disk_file.read_bytes() == payload

            dl = client.get(f"/api/v1/attachments/{att_id}")
            assert dl.status_code == 200
            assert dl.content == payload


def test_t1_attachment_multipart_upload_and_bot_library_artifact(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Multipart upload attaches to bot library with media/file types and overrides."""
    json_bytes = b'{"batch": 7, "status": "green"}'
    with server.client() as client:
        r_png = client.post(
            "/api/v1/attachments",
            files={"file": ("photo.png", _TINY_PNG, "image/png")},
            data={"thread_id": "thr_bot_chief"},
        )
        assert r_png.status_code == 201
        png_meta = r_png.json()
        assert png_meta["thread_id"] == "thr_bot_chief"
        assert png_meta["filename"] == "photo.png"
        assert png_meta["mime_type"] == "image/png"

        r_json = client.post(
            "/api/v1/attachments",
            params={"filename": "override.json", "thread_id": "thr_bot_chief"},
            files={"file": ("report.json", json_bytes, "application/json")},
        )
        assert r_json.status_code == 201
        json_meta = r_json.json()
        assert json_meta["thread_id"] == "thr_bot_chief"
        assert json_meta["filename"] == "override.json"

        lib_resp = client.get("/api/v1/bots/bot_chief/library")
        assert lib_resp.status_code == 200
        items = lib_resp.json()["items"]
        by_url: dict[str, dict[str, Any]] = {str(it["url"]): it for it in items}

        png_url = f"/api/v1/attachments/{png_meta['id']}"
        json_url = f"/api/v1/attachments/{json_meta['id']}"
        assert png_url in by_url
        assert by_url[png_url]["type"] == "media"
        assert by_url[png_url]["file_path"] == "photo.png"
        assert by_url[png_url]["size_bytes"] == len(_TINY_PNG)

        assert json_url in by_url
        assert by_url[json_url]["type"] == "file"
        assert by_url[json_url]["file_path"] == "override.json"
        assert by_url[json_url]["size_bytes"] == len(json_bytes)


async def test_t1_attachment_message_binding_and_artifact_delete_cleanup(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Bound attachment survives artifact delete; unreferenced is purged."""
    uploads_dir = server.tmp_dir / "uploads"
    bound_bytes = b"bound attachment content"
    async with server.async_client() as aclient:
        r_bound = await aclient.post(
            "/api/v1/attachments",
            params={"filename": "bound.txt", "thread_id": "thr_bot_chief"},
            headers={"Content-Type": "text/plain"},
            content=bound_bytes,
        )
        assert r_bound.status_code == 201
        bound_id = str(r_bound.json()["id"])
        bound_disk_path = uploads_dir / f"{bound_id}_bound.txt"
        assert bound_disk_path.is_file()

        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/note Attach log",
            attachment_ids=[bound_id],
        )
        bound_atts = turn.user_message.get("attachments", [])
        assert isinstance(bound_atts, list) and len(bound_atts) == 1
        assert bound_atts[0]["id"] == bound_id
        assert bound_atts[0]["filename"] == "bound.txt"

        lib_before = await aclient.get("/api/v1/bots/bot_chief/library")
        assert lib_before.status_code == 200
        bound_art = next(
            it
            for it in lib_before.json()["items"]
            if it["url"] == f"/api/v1/attachments/{bound_id}"
        )
        bound_art_id = str(bound_art["id"])

        async def _delete_bound_art() -> None:
            await asyncio.sleep(0.1)
            del_resp = await aclient.delete(f"/api/v1/artifacts/{bound_art_id}")
            assert del_resp.status_code == 200
            assert del_resp.json() == {"deleted": True}

        bound_task = asyncio.create_task(_delete_bound_art())
        bound_ev = await wait_for_sse_event(
            aclient,
            lambda f: (
                f.event_type == "artifact.deleted"
                and isinstance(f.data, dict)
                and f.data.get("payload", {}).get("artifact_id") == bound_art_id
            ),
            timeout=5.0,
        )
        await bound_task
        assert isinstance(bound_ev.data, dict)
        assert bound_ev.data["payload"]["bot_id"] == "bot_chief"

        # Library artifact is gone, yet message-bound attachment MUST remain 200 + on disk.
        lib_after_bound = await aclient.get("/api/v1/bots/bot_chief/library")
        assert lib_after_bound.status_code == 200
        assert all(it["id"] != bound_art_id for it in lib_after_bound.json()["items"])
        assert bound_disk_path.is_file()
        bound_dl = await aclient.get(f"/api/v1/attachments/{bound_id}")
        assert bound_dl.status_code == 200
        assert bound_dl.content == bound_bytes

        # Unreferenced attachment in bot library IS purged from DB, disk, and GET -> 404.
        r_clean = await aclient.post(
            "/api/v1/attachments",
            params={"filename": "cleanup.txt", "thread_id": "thr_bot_chief"},
            headers={"Content-Type": "text/plain"},
            content=b"to be cleaned up",
        )
        assert r_clean.status_code == 201
        clean_id = str(r_clean.json()["id"])
        disk_path = uploads_dir / f"{clean_id}_cleanup.txt"
        assert disk_path.is_file()

        lib_resp = await aclient.get("/api/v1/bots/bot_chief/library")
        assert lib_resp.status_code == 200
        art = next(
            it
            for it in lib_resp.json()["items"]
            if it["url"] == f"/api/v1/attachments/{clean_id}"
        )
        art_id = str(art["id"])

        async def _delete_art() -> None:
            await asyncio.sleep(0.1)
            del_resp = await aclient.delete(f"/api/v1/artifacts/{art_id}")
            assert del_resp.status_code == 200
            assert del_resp.json() == {"deleted": True}

        task = asyncio.create_task(_delete_art())
        ev = await wait_for_sse_event(
            aclient,
            lambda f: (
                f.event_type == "artifact.deleted"
                and isinstance(f.data, dict)
                and f.data.get("payload", {}).get("artifact_id") == art_id
            ),
            timeout=5.0,
        )
        await task
        assert isinstance(ev.data, dict)
        assert ev.data["payload"]["bot_id"] == "bot_chief"
        assert not disk_path.exists()
        assert (await aclient.get(f"/api/v1/attachments/{clean_id}")).status_code == 404


def test_t1_attachment_no_thread_and_channel_thread_skip_bot_library(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Uploads without thread_id or on channel thread do not create bot artifacts."""
    with server.client() as client:
        before_urls = {
            it["url"] for it in client.get("/api/v1/bots/bot_chief/library").json()["items"]
        }

        ch_resp = client.post(
            "/api/v1/channels",
            json={"name": "Attach Channel", "bot_ids": ["bot_chief", "bot_ops"]},
        )
        assert ch_resp.status_code == 201
        ch_thread = str(ch_resp.json()["thread_id"])

        r_none = client.post(
            "/api/v1/attachments",
            params={"filename": "orphan.txt"},
            headers={"Content-Type": "text/plain"},
            content=b"no thread",
        )
        assert r_none.status_code == 201
        r_ch = client.post(
            "/api/v1/attachments",
            params={"filename": "channel.txt", "thread_id": ch_thread},
            headers={"Content-Type": "text/plain"},
            content=b"channel thread",
        )
        assert r_ch.status_code == 201

        assert client.get(f"/api/v1/attachments/{r_none.json()['id']}").status_code == 200
        assert client.get(f"/api/v1/attachments/{r_ch.json()['id']}").status_code == 200

        after_urls = {
            it["url"] for it in client.get("/api/v1/bots/bot_chief/library").json()["items"]
        }
        assert after_urls == before_urls


def test_t1_workspace_files_default_project_listing_and_readme(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Workspace files lists seeded Grokbotclon project and reads README.md."""
    with server.client() as client:
        listing = client.get("/api/v1/computers/default/files")
        assert listing.status_code == 200
        body = listing.json()
        assert body["project"] == "Grokbotclon"
        names = {entry["name"] for entry in body["entries"]}
        assert "README.md" in names

        readme = client.get("/api/v1/computers/default/file", params={"path": "README.md"})
        assert readme.status_code == 200
        rd_json = readme.json()
        assert rd_json["rel_path"] == "README.md"
        assert rd_json["content"] == "# Grokbotclon E2E Workspace\n"
        assert rd_json["truncated"] is False


def test_t1_workspace_files_crud_mkdir_write_read_download_delete(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Full Workspace Files CRUD (mkdir, write, list, read, download, delete)."""
    with server.client() as client:
        mk = client.post(
            "/api/v1/computers/default/files/mkdir",
            json={"path": "reports/q1"},
        )
        assert mk.status_code == 201
        assert mk.json()["rel_path"] == "reports/q1"

        wr = client.post(
            "/api/v1/computers/default/files/write",
            json={"path": "reports/q1/summary.md", "content": "# Q1 Summary\nAll green.\n"},
        )
        assert wr.status_code == 200
        assert wr.json()["rel_path"] == "reports/q1/summary.md"

        ls = client.get("/api/v1/computers/default/files", params={"path": "reports/q1"})
        assert ls.status_code == 200
        assert [e["name"] for e in ls.json()["entries"]] == ["summary.md"]

        rd = client.get("/api/v1/computers/default/file", params={"path": "reports/q1/summary.md"})
        assert rd.status_code == 200
        assert rd.json()["content"] == "# Q1 Summary\nAll green.\n"

        dl = client.get(
            "/api/v1/computers/default/file/download",
            params={"path": "reports/q1/summary.md"},
        )
        assert dl.status_code == 200
        assert dl.content == b"# Q1 Summary\nAll green.\n"
        assert dl.headers.get("content-disposition") == 'attachment; filename="summary.md"'

        rm = client.delete("/api/v1/computers/default/files", params={"path": "reports"})
        assert rm.status_code == 200
        assert rm.json() == {"deleted": True}

        assert (
            client.get(
                "/api/v1/computers/default/file",
                params={"path": "reports/q1/summary.md"},
            ).status_code
            == 404
        )


def test_t1_workspace_files_raw_upload_and_binary_download(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Raw workspace upload saves binary PNG; /file rejects binary, /download works."""
    with server.client() as client:
        up = client.post(
            "/api/v1/computers/default/files/upload",
            params={"path": "assets", "name": "logo.png"},
            content=_TINY_PNG,
        )
        assert up.status_code == 201
        assert up.json() == {"rel_path": "assets/logo.png", "size_bytes": len(_TINY_PNG)}

        preview = client.get(
            "/api/v1/computers/default/file",
            params={"path": "assets/logo.png"},
        )
        assert preview.status_code == 400

        dl = client.get(
            "/api/v1/computers/default/file/download",
            params={"path": "assets/logo.png"},
        )
        assert dl.status_code == 200
        assert dl.content == _TINY_PNG
        assert dl.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "image/png"


def test_t1_workspace_files_multi_project_isolation_and_secret_redaction(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Multi-project isolation, safe src/config.py read, and inline secret scrub."""
    second_proj = server.projects_root / "SecondProj"
    second_proj.mkdir(parents=True, exist_ok=True)
    secret_tok = "sk-e2e-test-secret-99999999"

    with server.client() as client:
        w1 = client.post(
            "/api/v1/computers/default/files/write",
            json={
                "project": "SecondProj",
                "path": "src/config.py",
                "content": "PORT = 9090\n",
            },
        )
        assert w1.status_code == 200

        w2 = client.post(
            "/api/v1/computers/default/files/write",
            json={
                "project": "SecondProj",
                "path": "notes.txt",
                "content": f"api_key={secret_tok}\n",
            },
        )
        assert w2.status_code == 200

        ls_default = client.get("/api/v1/computers/default/files")
        assert ls_default.status_code == 200
        assert "notes.txt" not in {e["name"] for e in ls_default.json()["entries"]}

        ls_second = client.get(
            "/api/v1/computers/default/files",
            params={"project": "SecondProj"},
        )
        assert ls_second.status_code == 200
        assert {e["name"] for e in ls_second.json()["entries"]} == {"src", "notes.txt"}

        cfg = client.get(
            "/api/v1/computers/default/file",
            params={"project": "SecondProj", "path": "src/config.py"},
        )
        assert cfg.status_code == 200
        assert cfg.json()["content"] == "PORT = 9090\n"

        notes = client.get(
            "/api/v1/computers/default/file",
            params={"project": "SecondProj", "path": "notes.txt"},
        )
        assert notes.status_code == 200
        assert secret_tok not in notes.json()["content"]


def test_t1_workspace_files_listing_filters_internal_dirs_and_escaping_symlinks(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F3): Directory listing skips .git/.venv/__pycache__/.DS_Store & bad symlinks."""
    proj = server.projects_root / "Grokbotclon"
    (proj / ".git").mkdir(exist_ok=True)
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (proj / ".venv").mkdir(exist_ok=True)
    (proj / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (proj / "__pycache__").mkdir(exist_ok=True)
    (proj / "__pycache__" / "x.pyc").write_bytes(b"\x00\x01")
    (proj / ".DS_Store").write_bytes(b"\x00\x00")
    (proj / "visible.txt").write_text("ok\n", encoding="utf-8")

    outside = server.tmp_dir / "outside_target.txt"
    outside.write_text("outside", encoding="utf-8")
    (proj / "broken_link.txt").symlink_to(proj / "does_not_exist.txt")
    (proj / "escape_link.txt").symlink_to(outside)

    with server.client() as client:
        ls = client.get("/api/v1/computers/default/files")
        assert ls.status_code == 200
        names = {e["name"] for e in ls.json()["entries"]}
        assert "README.md" in names
        assert "visible.txt" in names
        for hidden in (
            ".git",
            ".venv",
            "__pycache__",
            ".DS_Store",
            "broken_link.txt",
            "escape_link.txt",
        ):
            assert hidden not in names


def test_t1_attachment_safe_mimes_inline_headers(server: IsolatedServer) -> None:
    """Tier 1 (F3): Safe MIME types serve inline with nosniff and CSP sandbox."""
    safe_cases: list[tuple[str, str, bytes]] = [
        ("pic.png", "image/png", _TINY_PNG),
        ("meta.json", "application/json", b'{"a":1}'),
        ("clip.mp3", "audio/mpeg", b"ID3\x03\x00"),
        ("clip.wav", "audio/wav", b"RIFF\x00\x00\x00\x00WAVE"),
        ("readme.txt", "text/plain", b"plain text"),
        ("raw.bin", "application/octet-stream", b"\x01\x02\x03\x04"),
    ]
    with server.client() as client:
        for fname, mime, data in safe_cases:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=data,
            )
            assert up.status_code == 201
            att_id = str(up.json()["id"])

            dl = client.get(f"/api/v1/attachments/{att_id}")
            assert dl.status_code == 200
            _assert_xss_hardened_headers(
                dl,
                expected_disposition="inline",
                expected_filename=fname,
                expected_mime=mime,
            )


# ==============================================================================
# Tier 2 Tests (12 tests)
# ==============================================================================


def test_t2_attachment_stored_xss_active_mimes_force_attachment_sandbox(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Active XSS MIME types force attachment disposition + nosniff + sandbox."""
    active_cases: list[tuple[str, str, bytes]] = [
        ("poc.html", "text/html", b"<script>alert(1)</script>"),
        ("vec.svg", "image/svg+xml", b"<svg onload='alert(1)'/>"),
        ("app.js", "application/javascript", b"alert(document.cookie);"),
        ("legacy.js", "text/javascript", b"alert(1);"),
        ("page.xhtml", "application/xhtml+xml", b"<html xmlns='http://www.w3.org/1999/xhtml'/>"),
        ("feed.xml", "text/xml", b"<?xml version='1.0'?><x/>"),
    ]
    with server.client() as client:
        for fname, mime, payload in active_cases:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert up.status_code == 201
            dl = client.get(f"/api/v1/attachments/{up.json()['id']}")
            assert dl.status_code == 200
            _assert_xss_hardened_headers(
                dl,
                expected_disposition="attachment",
                expected_filename=fname,
                expected_mime=mime,
            )


def test_t2_attachment_stored_xss_extension_sniffing_and_filename_sanitization(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Active extensions with spoofed safe MIME & dirty names force attachment."""
    ext_cases: list[tuple[str, str]] = [
        ("payload.html", "text/plain"),
        ("payload.htm", "application/octet-stream"),
        ("icon.svg", "text/plain"),
        ("bundle.js", "text/plain"),
        ("mod.mjs", "application/octet-stream"),
        ("doc.xml", "text/plain"),
    ]
    with server.client() as client:
        for fname, spoofed_mime in ext_cases:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": spoofed_mime},
                content=b"<script>alert('xss')</script>",
            )
            assert up.status_code == 201
            dl = client.get(f"/api/v1/attachments/{up.json()['id']}")
            assert dl.status_code == 200
            _assert_xss_hardened_headers(
                dl,
                expected_disposition="attachment",
                expected_filename=fname,
                expected_mime=dl.headers["content-type"].split(";", 1)[0].strip(),
            )

        # Safe extension .txt with active MIME text/html -> still forced attachment
        r_mime = client.post(
            "/api/v1/attachments",
            params={"filename": "note.txt"},
            headers={"Content-Type": "text/html"},
            content=b"<b>hi</b>",
        )
        assert r_mime.status_code == 201
        dl_mime = client.get(f"/api/v1/attachments/{r_mime.json()['id']}")
        _assert_xss_hardened_headers(
            dl_mime,
            expected_disposition="attachment",
            expected_filename="note.txt",
            expected_mime="text/html",
        )

        # Path/quote sanitization in filename
        r_dirty = client.post(
            "/api/v1/attachments",
            params={"filename": '../../evil"xss.html'},
            headers={"Content-Type": "text/html"},
            content=b"<script>alert(1)</script>",
        )
        assert r_dirty.status_code == 201
        assert r_dirty.json()["filename"] == "evil_xss.html"
        dl_dirty = client.get(f"/api/v1/attachments/{r_dirty.json()['id']}")
        _assert_xss_hardened_headers(
            dl_dirty,
            expected_disposition="attachment",
            expected_filename="evil_xss.html",
            expected_mime="text/html",
        )


def test_t2_attachment_exact_25mib_boundary_succeeds(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Exact 25 MiB streaming attachment upload succeeds (201)."""
    uploads_dir = server.tmp_dir / "uploads"
    with server.client(timeout=30.0) as client:
        resp = client.post(
            "/api/v1/attachments",
            params={"filename": "exact25.bin"},
            headers={"Content-Type": "application/octet-stream"},
            content=_iter_fixed_bytes(_MAX_ATTACHMENT_BYTES),
        )
        assert resp.status_code == 201
        meta = resp.json()
        assert meta["size_bytes"] == _MAX_ATTACHMENT_BYTES
        disk_path = uploads_dir / f"{meta['id']}_exact25.bin"
        assert disk_path.is_file()
        assert disk_path.stat().st_size == _MAX_ATTACHMENT_BYTES


def test_t2_attachment_over_25mib_streaming_413_and_no_disk_or_db_leak(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): 25 MiB + 1 B chunked stream fails with 413 and leaves no disk/DB leak."""
    uploads_dir = server.tmp_dir / "uploads"
    with server.client(timeout=30.0) as client:
        before_items = client.get("/api/v1/bots/bot_chief/library").json()["items"]

        resp = client.post(
            "/api/v1/attachments",
            params={"filename": "over25.bin", "thread_id": "thr_bot_chief"},
            headers={"Content-Type": "application/octet-stream"},
            content=_iter_fixed_bytes(_MAX_ATTACHMENT_BYTES + 1),
        )
        assert resp.status_code == 413
        assert "26214400" in resp.json()["detail"]

        if uploads_dir.exists():
            assert list(uploads_dir.iterdir()) == []
        after_items = client.get("/api/v1/bots/bot_chief/library").json()["items"]
        assert len(after_items) == len(before_items)


def test_t2_attachment_over_25mib_content_length_fast_reject_413(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Oversized Content-Length header triggers immediate 413 without streaming."""
    uploads_dir = server.tmp_dir / "uploads"
    status_code, raw_resp = _send_raw_oversized_content_length(
        "127.0.0.1",
        server.port,
        "/api/v1/attachments?filename=hdr25.bin",
        _MAX_ATTACHMENT_BYTES + 1,
    )
    assert status_code == 413, f"Expected 413, got raw={raw_resp!r}"
    assert not uploads_dir.exists() or list(uploads_dir.iterdir()) == []


def test_t2_workspace_files_exact_50mib_boundary_succeeds(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Exact 50 MiB workspace upload succeeds (201) and downloads cleanly."""
    proj = server.projects_root / "Grokbotclon"
    with server.client(timeout=45.0) as client:
        up = client.post(
            "/api/v1/computers/default/files/upload",
            params={"name": "exact50.bin"},
            content=_iter_fixed_bytes(_MAX_WORKSPACE_FILE_BYTES),
        )
        assert up.status_code == 201
        assert up.json() == {"rel_path": "exact50.bin", "size_bytes": _MAX_WORKSPACE_FILE_BYTES}
        disk_path = proj / "exact50.bin"
        assert disk_path.is_file()
        assert disk_path.stat().st_size == _MAX_WORKSPACE_FILE_BYTES

        with client.stream(
            "GET",
            "/api/v1/computers/default/file/download",
            params={"path": "exact50.bin"},
        ) as dl:
            assert dl.status_code == 200
            total = sum(len(chunk) for chunk in dl.iter_bytes(chunk_size=_MIB))
            assert total == _MAX_WORKSPACE_FILE_BYTES


def test_t2_workspace_files_over_50mib_upload_write_and_download_413(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): >50 MiB upload, write, and download all reject with 413 and clean up."""
    proj = server.projects_root / "Grokbotclon"
    with server.client(timeout=45.0) as client:
        up_over = client.post(
            "/api/v1/computers/default/files/upload",
            params={"name": "over50.bin"},
            content=_iter_fixed_bytes(_MAX_WORKSPACE_FILE_BYTES + 1),
        )
        assert up_over.status_code == 413
        assert not (proj / "over50.bin").exists()

        wr_over = client.post(
            "/api/v1/computers/default/files/write",
            headers={"Content-Type": "application/json"},
            content=_iter_json_write_payload("over50.txt", _MAX_WORKSPACE_FILE_BYTES + 1),
        )
        gc.collect()
        assert wr_over.status_code == 413
        assert not (proj / "over50.txt").exists()

        sparse_path = proj / "sparse_over50.bin"
        with sparse_path.open("wb") as handle:
            handle.seek(_MAX_WORKSPACE_FILE_BYTES)
            handle.write(b"Z")
        dl_over = client.get(
            "/api/v1/computers/default/file/download",
            params={"path": "sparse_over50.bin"},
        )
        assert dl_over.status_code == 413


def test_t2_symlink_delete_safety_in_project_file_dir_and_broken_links(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Deleting in-project file/dir/broken symlinks unlinks ONLY the symlink."""
    proj = server.projects_root / "Grokbotclon"
    real_file = proj / "real.txt"
    real_file.write_text("keep me\n", encoding="utf-8")
    subdir = proj / "subdir"
    subdir.mkdir()
    nested = subdir / "nested.txt"
    nested.write_text("keep nested\n", encoding="utf-8")

    (proj / "link.txt").symlink_to(real_file)
    (proj / "dir_link").symlink_to(subdir)
    (proj / "broken_link.txt").symlink_to(proj / "missing_target.txt")

    with server.client() as client:
        for link_name in ("link.txt", "dir_link", "broken_link.txt"):
            rm = client.delete(
                "/api/v1/computers/default/files",
                params={"path": link_name},
            )
            assert rm.status_code == 200
            assert rm.json() == {"deleted": True}
            assert not (proj / link_name).is_symlink()

    assert real_file.is_file() and real_file.read_text(encoding="utf-8") == "keep me\n"
    assert nested.is_file() and nested.read_text(encoding="utf-8") == "keep nested\n"


def test_t2_symlink_escape_delete_and_read_blocked_403(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Escaping symlinks outside project root are blocked without modifying target."""
    proj = server.projects_root / "Grokbotclon"
    outside_dir = server.tmp_dir / "outside_secret_dir"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("outside secret\n", encoding="utf-8")

    escape_file_link = proj / "escape_link.txt"
    escape_dir_link = proj / "dir_escape"
    escape_file_link.symlink_to(outside_file)
    escape_dir_link.symlink_to(outside_dir)

    with server.client() as client:
        for rel in ("escape_link.txt", "dir_escape/secret.txt"):
            assert (
                client.delete("/api/v1/computers/default/files", params={"path": rel}).status_code
                == 403
            )
            assert (
                client.get(
                    "/api/v1/computers/default/file/download",
                    params={"path": rel},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/computers/default/files/write",
                    json={"path": rel, "content": "overwrite"},
                ).status_code
                == 403
            )
            assert (
                client.get("/api/v1/computers/default/file", params={"path": rel}).status_code
                == 403
            )

        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"path": "dir_escape"},
            ).status_code
            == 403
        )

    assert outside_file.read_text(encoding="utf-8") == "outside secret\n"
    assert escape_file_link.is_symlink()
    assert escape_dir_link.is_symlink()


def test_t2_symlink_into_git_blocked_and_immutable(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Symlinks pointing into .git/ are blocked across write/read/dl/list/del."""
    proj = server.projects_root / "Grokbotclon"
    git_dir = proj / ".git"
    git_hooks = git_dir / "hooks"
    git_hooks.mkdir(parents=True, exist_ok=True)
    git_config = git_dir / "config"
    original_cfg = "[core]\n\trepositoryformatversion = 0\n"
    git_config.write_text(original_cfg, encoding="utf-8")
    hook_target = git_hooks / "post-checkout"
    assert not hook_target.exists()

    cfg_link = proj / "git_cfg_link"
    hook_link = proj / "git_hook_link"
    dir_link = proj / "git_dir_link"
    cfg_link.symlink_to(git_config)
    hook_link.symlink_to(hook_target)
    dir_link.symlink_to(git_dir)

    symlink_paths = (
        "git_cfg_link",
        "git_hook_link",
        "git_dir_link/config",
        "git_dir_link/hooks/post-checkout",
    )
    with server.client() as client:
        assert client.get(
            "/api/v1/computers/default/files",
            params={"path": "git_dir_link"},
        ).status_code in {400, 403}

        for rel in symlink_paths:
            assert client.post(
                "/api/v1/computers/default/files/write",
                json={"path": rel, "content": "#!/bin/sh\necho pwned\n"},
            ).status_code in {400, 403}
            assert client.get(
                "/api/v1/computers/default/file",
                params={"path": rel},
            ).status_code in {400, 403}
            assert client.get(
                "/api/v1/computers/default/file/download",
                params={"path": rel},
            ).status_code in {400, 403}
            assert client.delete(
                "/api/v1/computers/default/files",
                params={"path": rel},
            ).status_code in {400, 403}

    assert git_config.read_text(encoding="utf-8") == original_cfg
    assert not hook_target.exists()
    assert cfg_link.is_symlink()
    assert hook_link.is_symlink()
    assert dir_link.is_symlink()


def test_t2_sensitive_filenames_blocked_403_across_all_file_endpoints(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Sensitive filenames (.env, .pem, .key, .db, .ssh/*, etc.) return 403."""
    proj = server.projects_root / "Grokbotclon"
    sensitive_paths = (
        ".env",
        ".env.production",
        "server.pem",
        "tls.key",
        "app.sqlite3",
        "state.db",
        ".ssh/authorized_keys",
        ".ssh/config",
        ".ssh/id_ed25519",
        ".aws/config",
        "secrets.json",
        "credentials.json",
        ".npmrc",
        ".netrc",
        ".pypirc",
        "my_secret.txt",
    )
    for rel in sensitive_paths:
        target = proj / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("SENSITIVE=1\n", encoding="utf-8")

    with server.client() as client:
        for rel in sensitive_paths:
            assert (
                client.get("/api/v1/computers/default/file", params={"path": rel}).status_code
                == 403
            )
            assert (
                client.get(
                    "/api/v1/computers/default/file/download",
                    params={"path": rel},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/computers/default/files/write",
                    json={"path": rel, "content": "x"},
                ).status_code
                == 403
            )
            assert (
                client.delete("/api/v1/computers/default/files", params={"path": rel}).status_code
                == 403
            )
            if "/" not in rel:
                assert (
                    client.post(
                        "/api/v1/computers/default/files/upload",
                        params={"name": rel},
                        content=b"x",
                    ).status_code
                    == 403
                )


def test_t2_path_traversal_and_git_metadata_blocked_400_or_403(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Path traversal, null bytes, backslash, empty path, and .git are blocked."""
    proj = server.projects_root / "Grokbotclon"
    (proj / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    (proj / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    traversal_inputs = (
        "../../etc/passwd",
        "sub/../../../etc/passwd",
        "..\\etc\\passwd",
        "bad\x00name",
        ".git/config",
    )
    with server.client() as client:
        for bad in traversal_inputs:
            assert (
                client.get("/api/v1/computers/default/files", params={"path": bad}).status_code
                == 400
            )
            r_file = client.get("/api/v1/computers/default/file", params={"path": bad})
            assert r_file.status_code in {400, 403}
            r_dl = client.get("/api/v1/computers/default/file/download", params={"path": bad})
            assert r_dl.status_code in {400, 403}
            r_mkdir = client.post("/api/v1/computers/default/files/mkdir", json={"path": bad})
            assert r_mkdir.status_code in {400, 403}
            r_write = client.post(
                "/api/v1/computers/default/files/write",
                json={"path": bad, "content": "x"},
            )
            assert r_write.status_code in {400, 403}
            r_del = client.delete("/api/v1/computers/default/files", params={"path": bad})
            assert r_del.status_code in {400, 403}

        for git_dir in (".git", ".git/", ".git/hooks"):
            assert client.get(
                "/api/v1/computers/default/files", params={"path": git_dir}
            ).status_code in {400, 403}
            assert client.get(
                "/api/v1/computers/default/file", params={"path": git_dir}
            ).status_code in {400, 403}
            assert client.get(
                "/api/v1/computers/default/file/download", params={"path": git_dir}
            ).status_code in {400, 403}
            assert client.post(
                "/api/v1/computers/default/files/mkdir", json={"path": git_dir}
            ).status_code in {400, 403}
            assert client.post(
                "/api/v1/computers/default/files/write",
                json={"path": git_dir, "content": "x"},
            ).status_code in {400, 403}
            assert client.delete(
                "/api/v1/computers/default/files", params={"path": git_dir}
            ).status_code in {400, 403}

        for bad_name in ("..", ".", "a/b", "a\\b", "bad\x00.txt", ""):
            r_up = client.post(
                "/api/v1/computers/default/files/upload",
                params={"name": bad_name},
                content=b"x",
            )
            assert r_up.status_code in {400, 403}

        assert client.get("/api/v1/computers/default/file", params={"path": ""}).status_code == 400
        assert (
            client.post("/api/v1/computers/default/files/mkdir", json={"path": ""}).status_code
            == 400
        )


def test_t2_missing_resources_404_and_auth_enforcement_401(
    server: IsolatedServer,
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F3): Missing attachments/files return 404/400; auth_server enforces 401 -> 200."""
    with server.client() as client:
        assert client.get("/api/v1/attachments/att_missing").status_code == 404
        assert client.delete("/api/v1/artifacts/art_missing").status_code == 404
        assert (
            client.get("/api/v1/computers/default/files", params={"path": "nope"}).status_code
            == 400
        )
        assert (
            client.get("/api/v1/computers/default/file", params={"path": "nope.txt"}).status_code
            == 404
        )
        assert (
            client.get(
                "/api/v1/computers/default/file/download",
                params={"path": "nope.txt"},
            ).status_code
            == 404
        )
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"path": "nope.txt"},
            ).status_code
            == 404
        )

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as unauth:
        assert (
            unauth.post(
                "/api/v1/attachments",
                params={"filename": "u.txt"},
                content=b"hi",
            ).status_code
            == 401
        )
        assert unauth.get("/api/v1/attachments/att_1").status_code == 401
        assert unauth.get("/api/v1/computers/default/files").status_code == 401
        assert (
            unauth.post(
                "/api/v1/computers/default/files/write",
                json={"path": "x.txt", "content": "hi"},
            ).status_code
            == 401
        )
        assert (
            unauth.delete(
                "/api/v1/computers/default/files",
                params={"path": "README.md"},
            ).status_code
            == 401
        )

    with auth_server.client() as authed:
        up = authed.post(
            "/api/v1/attachments",
            params={"filename": "auth.txt"},
            headers={"Content-Type": "text/plain"},
            content=b"authed body",
        )
        assert up.status_code == 201
        att_id = str(up.json()["id"])
        assert authed.get(f"/api/v1/attachments/{att_id}").content == b"authed body"
        assert authed.get("/api/v1/computers/default/files").status_code == 200
        assert (
            authed.post(
                "/api/v1/computers/default/files/write",
                json={"path": "authed.txt", "content": "ok"},
            ).status_code
            == 200
        )
        assert (
            authed.delete(
                "/api/v1/computers/default/files",
                params={"path": "authed.txt"},
            ).status_code
            == 200
        )
