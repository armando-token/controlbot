"""N2 integration test for the M7 software factory 2-candidate demonstration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from src.factory.db import FactoryStore

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.n2
def test_factory_demo_subprocess_promotes_cand1_verifies_rollback_and_rejects_cand2(
    tmp_path: Path,
) -> None:
    lab_repo = tmp_path / "lab_repo"
    factory_db = tmp_path / "factory_state" / "factory.db"
    out_dir = tmp_path / "factory_artifacts"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.factory.demo",
            "--repo",
            str(lab_repo),
            "--db",
            str(factory_db),
            "--output-dir",
            str(out_dir),
            "--json",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    assert "RuntimeWarning" not in proc.stderr

    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["isolation_verified"] is True
    assert payload["rollback_verified"] is True
    assert payload["candidate_1"]["status"] == "promoted"
    assert payload["candidate_1"]["baseline_metric"] == 100.0
    assert payload["candidate_1"]["candidate_metric"] == 1.0
    assert Path(payload["manifest_path"]).exists()

    assert payload["candidate_2"]["status"] == "rejected"
    assert "identity_gate_failed" in payload["candidate_2"]["reason"]
    assert payload["final_main_head"] == payload["promoted_commit"]

    store = FactoryStore(factory_db)
    lessons = store.list_lessons()
    assert len(lessons) == 2
    assert {les.outcome for les in lessons} == {"PROMOTED", "REJECTED"}
    runs = store.list_candidate_runs()
    assert len(runs) == 2
    assert runs[0].status == "PROMOTED"
    assert runs[1].status == "REJECTED"
    assert runs[1].identity_gate_passed is False
