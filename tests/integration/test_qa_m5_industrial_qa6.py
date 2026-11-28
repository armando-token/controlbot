"""Integration tests for M5 CB-11, CB-12, CB-13 & QA-6 closeout workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from src.n3_probe import run_n3_probe
from src.qa.cli import main
from src.qa.isolation import IsolatedLabServer
from src.qa.models import RunRecord
from src.qa.scenarios._common import _EphemeralLabStack
from src.qa.ux_metrics import contains_unredacted_secret_m3

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_runs(camp_dir: Path) -> list[RunRecord]:
    return [
        RunRecord.model_validate_json(line)
        for line in (camp_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.n2
def test_m5_cb11_cb12_cb13_and_qa6_closeout_isolated_e2e(tmp_path: Path) -> None:
    """Exercise CB-11..CB-13 end-to-end plus QA-6 2x same-SHA closeout & variance stats."""
    camp_dir = tmp_path / "camp_m5_qa6"
    with (
        _EphemeralLabStack(fixture_mode="default") as lab_stack,
        IsolatedLabServer(
            repo_root=_REPO_ROOT,
            base_dir=tmp_path / "studio_lab",
            extra_env=lab_stack.env_vars(),
        ) as studio,
    ):
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    studio.base_url,
                    "--output-dir",
                    str(camp_dir),
                    "--no-build-frontend",
                    "--skip-browser",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

        # Run CB-13 first so tail of runs stays consecutive green for QA-6 same_sha_passes
        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_dir),
                    "--cases",
                    "CB-13",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

        # Two full same-SHA green passes on CB-00, CB-11, CB-12 (>=3 total runs for variance)
        for _ in range(2):
            assert (
                main(
                    [
                        "scan",
                        "--campaign-dir",
                        str(camp_dir),
                        "--cases",
                        "CB-00,CB-11,CB-12",
                        "--repo-root",
                        str(_REPO_ROOT),
                    ]
                )
                == 0
            )

        assert (
            main(
                [
                    "report",
                    "--campaign-dir",
                    str(camp_dir),
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

        runs = _load_runs(camp_dir)
        by_case: dict[str, list[RunRecord]] = {}
        for r in runs:
            by_case.setdefault(r.case_id, []).append(r)

        assert len(by_case["CB-11"]) == 2
        assert all(r.passed for r in by_case["CB-11"])
        assert all(
            r.assertions.get("facility_b_studio_chat_scope_and_provenance") is True
            for r in by_case["CB-11"]
        )
        assert all(
            r.assertions.get("scada_maintenance_http_405_readonly") is True
            for r in by_case["CB-11"]
        )

        assert len(by_case["CB-12"]) == 2
        assert all(r.passed for r in by_case["CB-12"])
        assert all(
            r.assertions.get("auth_expired_401_pause_and_resume_verified") is True
            for r in by_case["CB-12"]
        )
        assert all(
            r.assertions.get("sigterm_restart_wal_and_sse_replay") is True
            for r in by_case["CB-12"]
        )

        n3_status = run_n3_probe().overall_status
        cb13_rec = by_case["CB-13"][0]
        if n3_status != "READY":
            assert cb13_rec.passed is False
            assert cb13_rec.assertions.get("n3_ready") is False
            assert cb13_rec.blocked_reason and "verify_n3_linux.sh" in cb13_rec.blocked_reason
        else:
            assert cb13_rec.passed is True

        handoff_text = (camp_dir / "HANDOFF.md").read_text(encoding="utf-8")
        daily_text = (camp_dir / "daily_report.md").read_text(encoding="utf-8")
        assert "**Open P0**: `0`" in daily_text
        assert "**Open P1**: `0`" in daily_text
        assert "## N3 & Environmental Blockers" in daily_text
        assert "## N3 & Environmental Blockers" in handoff_text
        assert "Same-SHA Passes" in daily_text
        assert not contains_unredacted_secret_m3(
            {
                "handoff": handoff_text,
                "daily": daily_text,
                "runs": [json.loads(r.model_dump_json()) for r in runs],
            }
        )
        assert studio.cap_secret not in handoff_text
        assert studio.cap_secret not in daily_text
