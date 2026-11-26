"""Unit tests for Milestone M5 Track B fixes (store, workspace/computer .git & symlinks, PTY)."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from src.web.app import create_app
from src.web.live_terminal import LiveTerminalSession
from src.web.v1.store import WorkspaceStore
from src.web.workspace import (
    _has_git_segment,
    _resolve_relative_project_path,
    list_project_files,
    read_project_file,
)


def test_delete_artifact_respects_message_attachments_json_and_prefixes(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "ws.sqlite3")
    try:
        bound_path = tmp_path / "uploads" / "att_1_bound.txt"
        bound_path.parent.mkdir(parents=True, exist_ok=True)
        bound_path.write_text("bound", encoding="utf-8")

        store.create_attachment(
            "att_1",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="bound.txt",
            mime_type="text/plain",
            size_bytes=5,
            storage_path=str(bound_path),
        )
        # Bind att_1 on a DIFFERENT thread to verify store checks all messages, not just one thread
        other_thr = store.create_channel({"name": "Other", "bot_ids": ["bot_chief", "bot_ops"]})
        store.create_message(
            thread_id=other_thr["id"],
            sender_type="user",
            sender_name="Operator",
            content="see attachment",
            attachments=[
                {"id": "att_1", "filename": "bound.txt", "mime_type": "text/plain", "size_bytes": 5}
            ],
        )
        art_bound = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="bound.txt",
            url="/api/v1/attachments/att_1?token=ignored",
        )
        del_bound = store.delete_artifact(art_bound["id"])
        assert del_bound is not None
        assert del_bound["deleted"] is True
        assert del_bound["attachment_path"] is None
        assert store.get_attachment_record("att_1") is not None

        # Prefix collision check: att_10 is unreferenced even though att_1 is bound,
        # and att_1 is NOT matched by a message referencing att_10 only.
        unrel_path = tmp_path / "uploads" / "att_10_clean.txt"
        unrel_path.write_text("clean", encoding="utf-8")
        store.create_attachment(
            "att_10",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="clean.txt",
            mime_type="text/plain",
            size_bytes=5,
            storage_path=str(unrel_path),
        )
        art_clean = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="clean.txt",
            url="/api/v1/attachments/att_10",
        )
        del_clean = store.delete_artifact(art_clean["id"])
        assert del_clean is not None
        assert del_clean["deleted"] is True
        assert del_clean["attachment_path"] == str(unrel_path)
        assert store.get_attachment_record("att_10") is None
    finally:
        store.close()


def test_messages_metadata_json_crud_scrubbing_and_legacy_migration(tmp_path: Path) -> None:
    db_file = tmp_path / "legacy_workspace.sqlite3"
    # Create legacy messages table lacking metadata_json before opening WorkspaceStore
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            """
            CREATE TABLE messages (
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
                conversation_id TEXT,
                model_id TEXT,
                status TEXT NOT NULL DEFAULT 'done',
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

    store = WorkspaceStore(db_file)
    try:
        cols = {str(r[1]) for r in store._conn.execute("PRAGMA table_info(messages)").fetchall()}
        assert "metadata_json" in cols
        migs = [
            int(r[0])
            for r in store._conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert migs == [1, 2]

        created = store.create_message(
            thread_id="thr_bot_chief",
            sender_type="bot",
            sender_bot_id="bot_chief",
            sender_name="Chief of Staff",
            content="Check complete",
            metadata={"verdict": "verified", "note": "sk-secret123456789"},
        )
        assert created["metadata"]["verdict"] == "verified"
        assert "sk-secret123456789" not in json.dumps(created["metadata"])

        updated = store.update_message(
            created["id"],
            {"metadata": json.dumps({"verdict": "stale_data", "api_key": "sk-anothersecret99"})},
        )
        assert updated["metadata"]["verdict"] == "stale_data"
        assert "sk-anothersecret99" not in json.dumps(updated["metadata"])

        updated2 = store.update_message(
            created["id"],
            {"metadata": {"verdict": "asset_not_found"}},
        )
        assert updated2["metadata"] == {"verdict": "asset_not_found"}
    finally:
        store.close()


def test_git_segment_and_symlink_blocking_in_workspace_and_computer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "DemoProj"
    (proj / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    git_cfg = proj / ".git" / "config"
    git_cfg.write_text("[core]\n", encoding="utf-8")
    (proj / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (proj / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    (proj / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (proj / "readme.txt").write_text("hello\n", encoding="utf-8")

    (proj / "git_cfg_link").symlink_to(git_cfg)
    (proj / "git_hook_link").symlink_to(proj / ".git" / "hooks" / "post-checkout")
    (proj / "git_dir_link").symlink_to(proj / ".git")
    (proj / "env_link.txt").symlink_to(proj / ".env")
    (proj / "ok_link.txt").symlink_to(proj / "readme.txt")
    (proj / "broken_ok.txt").symlink_to(proj / "missing.txt")

    assert _has_git_segment(Path(".git/config")) is True
    assert _has_git_segment(Path("sub/.GIT/HEAD")) is True
    assert _has_git_segment(Path(".github/workflows/ci.yml")) is False
    assert _has_git_segment(Path(".gitignore")) is False

    for bad in (
        ".git",
        ".git/config",
        ".GIT/HEAD",
        "git_cfg_link",
        "git_hook_link",
        "git_dir_link",
    ):
        with pytest.raises(ValueError, match="restricted"):
            _resolve_relative_project_path(proj, bad, follow_symlinks=True)
        with pytest.raises(ValueError, match="restricted"):
            _resolve_relative_project_path(proj, bad, follow_symlinks=False)

    assert _resolve_relative_project_path(proj, "ok_link.txt", follow_symlinks=False).name == (
        "ok_link.txt"
    )
    assert _resolve_relative_project_path(proj, "broken_ok.txt", follow_symlinks=False).name == (
        "broken_ok.txt"
    )

    listing = list_project_files(projects_dir, "DemoProj", "")
    names = {e["name"] for e in listing["entries"]}
    assert "git_cfg_link" not in names
    assert "git_dir_link" not in names
    assert ".github" in names

    with pytest.raises(ValueError, match="restricted"):
        read_project_file(projects_dir, "DemoProj", "git_cfg_link")

    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))
    app = create_app(db_path=tmp_path / "git_sec.sqlite3")
    with TestClient(app) as client:
        assert (
            client.get(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": ".git/config"},
            ).status_code
            == 400
        )
        assert (
            client.get(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "git_dir_link"},
            ).status_code
            == 400
        )
        for rel in ("git_cfg_link", "git_hook_link", "git_dir_link/config", "env_link.txt"):
            assert (
                client.get(
                    "/api/v1/computers/default/file",
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
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "ok_link.txt"},
            ).status_code
            == 200
        )
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "DemoProj", "path": "broken_ok.txt"},
            ).status_code
            == 200
        )


async def test_live_terminal_controlling_tty_and_fg_sigint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    term = LiveTerminalSession(cwd=tmp_path)
    try:
        term.write("sleep 30\n")
        await asyncio.sleep(0.25)
        assert term._proc is not None and term._proc.poll() is None
        assert term._master_fd is not None
        fg_pgrp = os.tcgetpgrp(term._master_fd)
        assert fg_pgrp > 0
        assert fg_pgrp != term._proc.pid

        assert term.send_signal(signal.SIGINT) is True
        await asyncio.sleep(0.15)
        assert term._proc.poll() is None

        term.write("echo STILL_ALIVE\n")
        deadline = asyncio.get_running_loop().time() + 5.0
        collected = ""
        while asyncio.get_running_loop().time() < deadline:
            try:
                chunk = await asyncio.wait_for(term.output_queue.get(), timeout=0.4)
            except TimeoutError:
                continue
            if chunk is None:
                break
            collected += chunk
            if "STILL_ALIVE" in collected:
                break
        assert "STILL_ALIVE" in collected

        # Fallback to \x03 if tcgetpgrp fails: must NOT signal proc.pid directly
        killed_pids: list[int] = []

        def _fail_tcgetpgrp(fd: int) -> int:
            del fd
            raise OSError("no fg")

        def _spy_killpg(pgid: int, sig: int) -> None:
            del sig
            killed_pids.append(pgid)

        written: list[str] = []
        monkeypatch.setattr(os, "tcgetpgrp", _fail_tcgetpgrp)
        monkeypatch.setattr(os, "killpg", _spy_killpg)
        monkeypatch.setattr(term, "write", written.append)
        assert term.send_signal(signal.SIGINT) is True
        assert killed_pids == []
        assert written == ["\x03"]
    finally:
        monkeypatch.undo()
        term.close()


def test_symlink_loop_eloop_handled_gracefully_across_workspace_and_computer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "LoopProj"
    sub_dir = proj / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (proj / "readme.txt").write_text("hello\n", encoding="utf-8")
    (sub_dir / "nested.txt").write_text("nested\n", encoding="utf-8")

    # Cyclic symlink loop: loop_a -> loop_b -> loop_a
    (proj / "loop_a").symlink_to(proj / "loop_b")
    (proj / "loop_b").symlink_to(proj / "loop_a")
    # Benign non-loop symlinks must continue returning 200 on delete
    (proj / "ok_link.txt").symlink_to(proj / "readme.txt")
    (proj / "dir_link").symlink_to(sub_dir)
    (proj / "broken_link.txt").symlink_to(proj / "missing.txt")

    listing = list_project_files(projects_dir, "LoopProj", "")
    names = {e["name"] for e in listing["entries"]}
    assert "readme.txt" in names
    assert "loop_a" not in names
    assert "loop_b" not in names

    for follow in (True, False):
        with pytest.raises(ValueError, match="Invalid or escaping path"):
            _resolve_relative_project_path(proj, "loop_a", follow_symlinks=follow)
    with pytest.raises(ValueError, match="Invalid or escaping path"):
        read_project_file(projects_dir, "LoopProj", "loop_a")

    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))
    app = create_app(db_path=tmp_path / "loop_sec.sqlite3")
    with TestClient(app) as client:
        # Directory listing skips loop entries and succeeds (200)
        list_root = client.get(
            "/api/v1/computers/default/files",
            params={"project": "LoopProj", "path": ""},
        )
        assert list_root.status_code == 200
        assert any(e["name"] == "readme.txt" for e in list_root.json()["entries"])

        # Direct listing of loop target returns 400 (never 500)
        assert (
            client.get(
                "/api/v1/computers/default/files",
                params={"project": "LoopProj", "path": "loop_a"},
            ).status_code
            == 400
        )

        # All direct file endpoints on symlink loop return 403 (never 500)
        assert (
            client.get(
                "/api/v1/computers/default/file",
                params={"project": "LoopProj", "path": "loop_a"},
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/api/v1/computers/default/file/download",
                params={"project": "LoopProj", "path": "loop_a"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/computers/default/files/write",
                json={"project": "LoopProj", "path": "loop_a", "content": "x"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/computers/default/files/mkdir",
                json={"project": "LoopProj", "path": "loop_a"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/computers/default/files/upload",
                params={"project": "LoopProj", "path": "loop_a", "name": "evil.txt"},
                content=b"abc",
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/computers/default/files/upload",
                params={"project": "LoopProj", "path": "", "name": "loop_a"},
                content=b"abc",
            ).status_code
            == 403
        )
        assert (
            client.delete(
                "/api/v1/computers/default/files",
                params={"project": "LoopProj", "path": "loop_a"},
            ).status_code
            == 403
        )

        # Benign non-loop symlinks still delete cleanly with 200
        for benign in ("ok_link.txt", "dir_link", "broken_link.txt"):
            assert (
                client.delete(
                    "/api/v1/computers/default/files",
                    params={"project": "LoopProj", "path": benign},
                ).status_code
                == 200
            )
        assert (sub_dir / "nested.txt").is_file()


def test_delete_artifact_query_params_and_slash_isolation(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "ws_query.sqlite3")
    try:
        uploads = tmp_path / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)

        # 1. Sibling artifact with ?download=1 keeps attachment & returns attachment_path=None
        q_path = uploads / "att_q1.txt"
        q_path.write_text("q1", encoding="utf-8")
        store.create_attachment(
            "att_q1",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="q1.txt",
            mime_type="text/plain",
            size_bytes=2,
            storage_path=str(q_path),
        )
        a1 = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="q1-plain",
            url="/api/v1/attachments/att_q1",
        )
        a2 = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="q1-dl",
            url="/api/v1/attachments/att_q1?download=1",
        )
        res_a1 = store.delete_artifact(a1["id"])
        assert res_a1 is not None
        assert res_a1["attachment_path"] is None
        assert store.get_attachment_record("att_q1") is not None

        res_a2 = store.delete_artifact(a2["id"])
        assert res_a2 is not None
        assert res_a2["attachment_path"] == str(q_path)
        assert store.get_attachment_record("att_q1") is None

        # 2. Query string containing '/' (?next=/foo/bar) still extracts att_slash cleanly
        slash_path = uploads / "att_slash.txt"
        slash_path.write_text("slash", encoding="utf-8")
        store.create_attachment(
            "att_slash",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="slash.txt",
            mime_type="text/plain",
            size_bytes=5,
            storage_path=str(slash_path),
        )
        a_slash = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="slash",
            url="/api/v1/attachments/att_slash?next=/foo/bar",
        )
        res_slash = store.delete_artifact(a_slash["id"])
        assert res_slash is not None
        assert res_slash["attachment_path"] == str(slash_path)
        assert store.get_attachment_record("att_slash") is None

        # 3. att_1 vs att_10 isolation with query parameters
        p1 = uploads / "att_1.txt"
        p10 = uploads / "att_10.txt"
        p1.write_text("1", encoding="utf-8")
        p10.write_text("10", encoding="utf-8")
        store.create_attachment(
            "att_1",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="1.txt",
            mime_type="text/plain",
            size_bytes=1,
            storage_path=str(p1),
        )
        store.create_attachment(
            "att_10",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="10.txt",
            mime_type="text/plain",
            size_bytes=2,
            storage_path=str(p10),
        )
        art_1 = store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="1.txt",
            url="/api/v1/attachments/att_1?v=1",
        )
        store.create_artifact(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            artifact_type="file",
            title="10.txt",
            url="/api/v1/attachments/att_10?next=/a/b",
        )
        res_1 = store.delete_artifact(art_1["id"])
        assert res_1 is not None
        assert res_1["attachment_path"] == str(p1)
        assert store.get_attachment_record("att_1") is None
        assert store.get_attachment_record("att_10") is not None
    finally:
        store.close()


def test_create_message_and_delete_artifact_concurrent_no_orphans(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "ws_race.sqlite3")
    try:
        uploads = tmp_path / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        for idx in range(25):
            aid = f"att_race_{idx}"
            fpath = uploads / f"{aid}.txt"
            fpath.write_text(f"payload-{idx}", encoding="utf-8")
            store.create_attachment(
                aid,
                thread_id="thr_bot_chief",
                bot_id="bot_chief",
                filename=f"{aid}.txt",
                mime_type="text/plain",
                size_bytes=len(f"payload-{idx}"),
                storage_path=str(fpath),
            )
            art = store.create_artifact(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                artifact_type="file",
                title=f"{aid}.txt",
                url=f"/api/v1/attachments/{aid}",
            )
            atts = store.get_attachments_summary([aid])
            assert len(atts) == 1

            barrier = threading.Barrier(2)
            created_msgs: list[dict[str, object]] = []
            errors: list[BaseException] = []

            def _writer(
                b: threading.Barrier,
                i: int,
                att_list: list[dict[str, object]],
                out_msgs: list[dict[str, object]],
                err_list: list[BaseException],
            ) -> None:
                try:
                    b.wait(timeout=5.0)
                    msg = store.create_message(
                        thread_id="thr_bot_chief",
                        sender_type="user",
                        sender_name="Operator",
                        content=f"race {i}",
                        attachments=att_list,
                    )
                    out_msgs.append(msg)
                except BaseException as exc:  # pragma: no cover
                    err_list.append(exc)

            def _deleter(
                b: threading.Barrier,
                artifact_id: str,
                err_list: list[BaseException],
            ) -> None:
                try:
                    b.wait(timeout=5.0)
                    store.delete_artifact(artifact_id)
                except BaseException as exc:  # pragma: no cover
                    err_list.append(exc)

            t1 = threading.Thread(
                target=_writer,
                args=(barrier, idx, atts, created_msgs, errors),
            )
            t2 = threading.Thread(
                target=_deleter,
                args=(barrier, art["id"], errors),
            )
            t1.start()
            t2.start()
            t1.join(timeout=10.0)
            t2.join(timeout=10.0)
            assert not errors
            assert len(created_msgs) == 1
            msg_atts = created_msgs[0]["attachments"]
            assert isinstance(msg_atts, list)
            if msg_atts:
                assert store.get_attachment_record(aid) is not None
            else:
                assert store.get_attachment_record(aid) is None

        # Also verify direct attachment_ids resolution inside create_message's write_tx
        direct_path = uploads / "att_direct.txt"
        direct_path.write_text("direct", encoding="utf-8")
        store.create_attachment(
            "att_direct",
            thread_id="thr_bot_chief",
            bot_id="bot_chief",
            filename="direct.txt",
            mime_type="text/plain",
            size_bytes=6,
            storage_path=str(direct_path),
        )
        direct_msg = store.create_message(
            thread_id="thr_bot_chief",
            sender_type="user",
            sender_name="Operator",
            content="direct ids",
            attachment_ids=["att_direct", "att_missing"],
        )
        assert [a["id"] for a in direct_msg["attachments"]] == ["att_direct"]
    finally:
        store.close()
