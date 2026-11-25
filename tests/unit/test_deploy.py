"""N1 unit tests for M8 declarative deployment config, packaging, and rollback (F17)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from deploy.config import DeployConfigError, load_deploy_config, validate_deploy_config
from deploy.config import main as deploy_config_main
from deploy.package import (
    ManifestError,
    create_release_manifest,
    load_release_manifest,
    write_release_manifest,
)
from deploy.rollback import RollbackError, execute_rollback
from deploy.rollback import main as rollback_main

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.n1
def test_load_real_install_config_yaml_and_json_roundtrip(tmp_path: Path) -> None:
    cfg = load_deploy_config(
        _REPO_ROOT / "deploy" / "install_config.yaml",
        verify_facility=True,
        repo_root=_REPO_ROOT,
    )
    assert cfg.environment == "lab_offline"
    assert cfg.bind_address == "127.0.0.1"
    assert cfg.permissions.allow_external_egress is False
    assert cfg.permissions.factory_isolated is True
    assert cfg.offline_ops.egress_blocked is True
    assert "http://127.0.0.1:8101" in cfg.allowed_origins

    # JSON roundtrip
    json_path = tmp_path / "install_config.json"
    json_path.write_text(cfg.model_dump_json(indent=2), encoding="utf-8")
    loaded_json = load_deploy_config(json_path, verify_facility=True, repo_root=_REPO_ROOT)
    assert loaded_json == cfg


@pytest.mark.n1
def test_deploy_config_fails_closed_on_external_or_unconfigured_origins(
    tmp_path: Path,
) -> None:
    base_raw = load_deploy_config(
        _REPO_ROOT / "deploy" / "install_config.yaml",
        verify_facility=False,
    ).model_dump(mode="python")

    # External internet URL in allowed_origins
    bad_ext = dict(base_raw)
    bad_ext["allowed_origins"] = ["https://api.openai.com"]
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_ext, verify_facility=False)

    # Public IP in local_model.origin
    bad_llm = dict(base_raw)
    bad_llm["local_model"] = {**dict(base_raw["local_model"]), "origin": "http://8.8.8.8:8080"}
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_llm, verify_facility=False)

    # Empty allowed_origins
    bad_empty = dict(base_raw)
    bad_empty["allowed_origins"] = []
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_empty, verify_facility=False)

    # Wildcard 0.0.0.0 bind_address
    bad_bind = dict(base_raw)
    bad_bind["bind_address"] = "0.0.0.0"
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_bind, verify_facility=False)

    # Egress enabled / factory not isolated
    bad_egress = dict(base_raw)
    bad_egress["permissions"] = {**dict(base_raw["permissions"]), "allow_external_egress": True}
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_egress, verify_facility=False)

    bad_offline = dict(base_raw)
    bad_offline["offline_ops"] = {**dict(base_raw["offline_ops"]), "egress_blocked": False}
    with pytest.raises(DeployConfigError):
        validate_deploy_config(bad_offline, verify_facility=False)

    # Facility JSON declaring an app origin absent from allowed_origins
    bad_fac = tmp_path / "bad_facility.json"
    fac_data = json.loads((_REPO_ROOT / "lab" / "configs" / "facility_a.json").read_text())
    fac_data["apps"]["scada"]["origin"] = "http://127.0.0.1:9999"
    bad_fac.write_text(json.dumps(fac_data), encoding="utf-8")

    mismatch_raw = dict(base_raw)
    mismatch_raw["facility_config_path"] = str(bad_fac)
    with pytest.raises(DeployConfigError, match="missing from"):
        validate_deploy_config(mismatch_raw, verify_facility=True)

    # CLI returns non-zero without usage: on invalid config
    missing_cfg = tmp_path / "missing.yaml"
    assert deploy_config_main(["--config", str(missing_cfg)]) == 1


@pytest.mark.n1
def test_package_manifest_sha256_and_chain_linking(tmp_path: Path) -> None:
    proj = tmp_path / "app"
    (proj / "deploy").mkdir(parents=True)
    (proj / "lab" / "configs").mkdir(parents=True)
    (proj / "src").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname="app"\nversion="0.1.0"\n')
    (proj / "uv.lock").write_text("# lock v1\n")
    (proj / "src" / "main.py").write_text("VALUE = 1\n")
    (proj / "lab" / "configs" / "facility_a.json").write_text(
        (_REPO_ROOT / "lab" / "configs" / "facility_a.json").read_text()
    )
    (proj / "deploy" / "install_config.yaml").write_text(
        (_REPO_ROOT / "deploy" / "install_config.yaml").read_text()
    )

    releases_dir = tmp_path / "releases"
    m1 = create_release_manifest(
        root_dir=proj,
        install_config_path=proj / "deploy" / "install_config.yaml",
        version="0.1.0",
        release_id="rel-0.1.0",
    )
    m1_path = write_release_manifest(
        m1,
        tmp_path / "m1.json",
        releases_dir=releases_dir,
    )
    assert m1.previous_release_id is None
    assert any(a.relative_path == "src/main.py" for a in m1.artifacts)

    (proj / "src" / "main.py").write_text("VALUE = 2\n")
    m2 = create_release_manifest(
        root_dir=proj,
        install_config_path=proj / "deploy" / "install_config.yaml",
        version="0.2.0",
        release_id="rel-0.2.0",
        previous_manifest_path=m1_path,
    )
    m2_path = write_release_manifest(
        m2,
        tmp_path / "m2.json",
        releases_dir=releases_dir,
    )
    reloaded = load_release_manifest(m2_path)
    assert reloaded.previous_release_id == "rel-0.1.0"
    assert reloaded.previous_manifest_path == str(m1_path.resolve())


@pytest.mark.n1
def test_rollback_preserves_sqlite_wal_and_browser_profiles(tmp_path: Path) -> None:
    proj = tmp_path / "app"
    (proj / "deploy").mkdir(parents=True)
    (proj / "lab" / "configs").mkdir(parents=True)
    (proj / "src").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname="app"\nversion="0.1.0"\n')
    (proj / "uv.lock").write_text("# lock\n")
    (proj / "src" / "mod.py").write_text("VER = 1\n")
    (proj / "lab" / "configs" / "facility_a.json").write_text(
        (_REPO_ROOT / "lab" / "configs" / "facility_a.json").read_text()
    )

    state_root = tmp_path / "var_lib_grokbot"
    state_root.mkdir(parents=True)
    db_file = state_root / "grokbot.sqlite3"
    wal_file = state_root / "grokbot.sqlite3-wal"
    shm_file = state_root / "grokbot.sqlite3-shm"
    profile_meta = state_root / "profiles" / "operator_ro" / "p1" / "scada" / "session_meta.json"
    profile_meta.parent.mkdir(parents=True)

    db_file.write_bytes(b"SQLITE_DB_BYTES")
    wal_file.write_bytes(b"SQLITE_WAL_BYTES")
    shm_file.write_bytes(b"SQLITE_SHM_BYTES")
    profile_meta.write_text('{"cookie": "preserved"}\n', encoding="utf-8")

    cfg_dict = load_deploy_config(
        _REPO_ROOT / "deploy" / "install_config.yaml",
        verify_facility=False,
    ).model_dump(mode="json")
    cfg_dict["storage"]["sqlite_wal_path"] = str(db_file)
    cfg_dict["storage"]["profile_root"] = str(state_root / "profiles")
    cfg_path = proj / "deploy" / "install_config.json"
    cfg_path.write_text(json.dumps(cfg_dict, indent=2), encoding="utf-8")

    releases_dir = tmp_path / "releases"
    m1 = create_release_manifest(
        root_dir=proj,
        install_config_path=cfg_path,
        version="0.1.0",
        release_id="rel-0.1.0",
    )
    write_release_manifest(m1, tmp_path / "m1.json", releases_dir=releases_dir)

    m2 = create_release_manifest(
        root_dir=proj,
        install_config_path=cfg_path,
        version="0.2.0",
        release_id="rel-0.2.0",
        previous_manifest_path=releases_dir / "rel-0.1.0" / "manifest.json",
    )
    write_release_manifest(m2, tmp_path / "m2.json", releases_dir=releases_dir)

    res = execute_rollback(
        releases_dir=releases_dir,
        target_release_id="rel-0.1.0",
        root_dir=proj,
    )
    assert res.ok is True
    assert res.rolled_back_to_release_id == "rel-0.1.0"
    assert res.previous_active_release_id == "rel-0.2.0"
    assert res.state_preserved is True
    assert str(db_file) in res.preserved_state_paths
    assert str(wal_file) in res.preserved_state_paths
    assert str(shm_file) in res.preserved_state_paths
    assert str(state_root / "profiles") in res.preserved_state_paths

    # Verify WAL + profiles bytes were completely untouched
    assert db_file.read_bytes() == b"SQLITE_DB_BYTES"
    assert wal_file.read_bytes() == b"SQLITE_WAL_BYTES"
    assert shm_file.read_bytes() == b"SQLITE_SHM_BYTES"
    assert profile_meta.read_text(encoding="utf-8") == '{"cookie": "preserved"}\n'

    current_ptr = json.loads((releases_dir / "current_release.json").read_text(encoding="utf-8"))
    assert current_ptr["release_id"] == "rel-0.1.0"
    history_lines = (
        (releases_dir / "rollback_history.jsonl").read_text(encoding="utf-8").splitlines()
    )
    assert len(history_lines) == 1

    # Tampered artifact checksum must raise RollbackError
    (proj / "src" / "mod.py").write_text("TAMPERED = True\n")
    with pytest.raises(RollbackError, match="Checksum mismatch"):
        execute_rollback(
            releases_dir=releases_dir,
            target_release_id="rel-0.1.0",
            root_dir=proj,
        )


@pytest.mark.n1
def test_rollback_missing_or_corrupt_manifest_stderr_no_usage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "nonexistent_manifest.json"
    rc_missing = rollback_main(["--manifest", str(missing)])
    cap1 = capsys.readouterr()
    assert rc_missing != 0
    assert cap1.err.strip()
    assert "usage:" not in cap1.out.lower()
    assert "usage:" not in cap1.err.lower()

    corrupt = tmp_path / "corrupt_manifest.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    rc_corrupt = rollback_main(["--manifest", str(corrupt)])
    cap2 = capsys.readouterr()
    assert rc_corrupt != 0
    assert cap2.err.strip()
    assert "usage:" not in cap2.out.lower()
    assert "usage:" not in cap2.err.lower()

    with pytest.raises(ManifestError):
        load_release_manifest(corrupt)

    # Subprocess check ensuring zero usage: string on missing manifest
    proc = subprocess.run(
        [sys.executable, "-m", "deploy.rollback", "--manifest", str(missing)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert proc.stderr.strip()
    assert "usage:" not in proc.stdout.lower()
    assert "usage:" not in proc.stderr.lower()


@pytest.mark.n1
def test_deploy_templates_runbook_and_verify_n3_script_honesty() -> None:
    service_text = (_REPO_ROOT / "deploy" / "grokbot.service").read_text(encoding="utf-8")
    container_text = (_REPO_ROOT / "deploy" / "Containerfile").read_text(encoding="utf-8")
    runbook_text = (_REPO_ROOT / "deploy" / "OFFLINE_RUNBOOK.md").read_text(encoding="utf-8")
    script_path = _REPO_ROOT / "scripts" / "verify_n3_linux.sh"
    script_text = script_path.read_text(encoding="utf-8")

    assert "PENDING_N3_LINUX_ENV" in service_text
    assert "127.0.0.1" in service_text
    assert "PENDING_N3_LINUX_ENV" in container_text
    assert "tini" in container_text
    assert "PENDING_N3_LINUX_ENV" in runbook_text
    assert "PENDING_N3_LINUX_ENV" in script_text
    if os.name == "posix":
        assert os.access(script_path, os.X_OK)


@pytest.mark.n1
def test_deploy_config_human_output_install_and_manifest_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sqlite3

    from deploy.install import main as deploy_install_main

    rc = deploy_config_main(["--config", str(_REPO_ROOT / "deploy" / "install_config.yaml")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "local_http" in out
    assert "1.0.0" in out
    assert "http://127.0.0.1:8101" in out

    db_path = tmp_path / "prod_wal.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE sentinel (id INTEGER PRIMARY KEY, note TEXT);")
    conn.execute("INSERT INTO sentinel (note) VALUES ('intact');")
    conn.commit()
    conn.close()

    stage = tmp_path / "stage"
    inst_rc = deploy_install_main(
        [
            "--config",
            "deploy/install_config.yaml",
            "--db",
            str(db_path),
            "--target",
            str(stage),
            "--manifest-dir",
            str(stage),
            "--json",
        ]
    )
    assert inst_rc == 0
    manifest_data = json.loads((stage / "release_manifest.json").read_text(encoding="utf-8"))
    assert manifest_data["uv_lock_hash"]
    assert manifest_data["config_hash"]
    assert manifest_data["restore_command"]
    assert str(db_path) in manifest_data["state_preserve_paths"]

    check_conn = sqlite3.connect(db_path)
    try:
        rows = check_conn.execute("SELECT note FROM sentinel;").fetchall()
        assert rows == [("intact",)]
    finally:
        check_conn.close()


@pytest.mark.n1
def test_deploy_validate_and_manage_upgrade_and_rollback(tmp_path: Path) -> None:
    import sqlite3

    from deploy.manage import main as deploy_manage_main

    bad_cfg = tmp_path / "bad_deploy.json"
    bad_cfg.write_text(
        json.dumps(
            {
                "allowed_origins": ["https://external.invalid"],
                "permissions": ["scada:read"],
                "policy_version": "1.0.0",
                "backend_mode": "emulated",
                "ports": {"web": 8080},
                "storage_path": str(tmp_path / "unused.sqlite3"),
            }
        ),
        encoding="utf-8",
    )
    bad_proc = subprocess.run(
        [sys.executable, "-m", "deploy.validate", "--config", str(bad_cfg)],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_proc.returncode != 0

    db_path = tmp_path / "runtime_wal.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE sentinel (id INTEGER PRIMARY KEY, val TEXT);")
    conn.execute("INSERT INTO sentinel (val) VALUES ('keep-me');")
    conn.commit()
    conn.close()

    work_dir = tmp_path / "deploy_work"
    rc = deploy_manage_main(
        [
            "upgrade-and-rollback",
            "--config",
            str(_REPO_ROOT / "deploy" / "install_config.yaml"),
            "--db-path",
            str(db_path),
            "--work-dir",
            str(work_dir),
            "--json",
        ]
    )
    assert rc == 0
    assert (work_dir / "current_release.json").is_file()
    check_conn = sqlite3.connect(db_path)
    try:
        assert check_conn.execute("SELECT val FROM sentinel;").fetchall() == [("keep-me",)]
    finally:
        check_conn.close()


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_18_package_quotes_spaces_and_rollback_rejects_symlinks(tmp_path: Path) -> None:
    import shlex
    import shutil

    from deploy.package import create_release_manifest, write_release_manifest
    from deploy.rollback import RollbackError, execute_rollback

    spaced_root = tmp_path / "dir with spaces"
    spaced_root.mkdir(parents=True, exist_ok=True)
    for rel_dir in ("src", "lab", "deploy", "ops", "scripts"):
        shutil.copytree(_REPO_ROOT / rel_dir, spaced_root / rel_dir)
    shutil.copy2(_REPO_ROOT / "pyproject.toml", spaced_root / "pyproject.toml")
    shutil.copy2(_REPO_ROOT / "uv.lock", spaced_root / "uv.lock")

    manifest = create_release_manifest(
        root_dir=spaced_root,
        install_config_path=spaced_root / "deploy" / "install_config.yaml",
    )
    expected_quoted = shlex.quote(str(spaced_root.resolve()))
    assert f"--root-dir {expected_quoted}" in manifest.restore_command

    manifest_path = spaced_root / "deploy" / "release_manifest.json"
    write_release_manifest(manifest, manifest_path)

    # Replace a packaged artifact with a symlink -> execute_rollback must reject it
    outside_target = tmp_path / "outside_target.py"
    outside_target.write_bytes((spaced_root / "src" / "__init__.py").read_bytes())
    artifact_path = spaced_root / "src" / "__init__.py"
    artifact_path.unlink()
    artifact_path.symlink_to(outside_target)

    with pytest.raises(RollbackError, match="Symlinked artifact"):
        execute_rollback(
            manifest_path=manifest_path,
            root_dir=spaced_root,
            state_dir=tmp_path / "state",
            verify_checksums=True,
        )
