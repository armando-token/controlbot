"""Linux-only N3 acceptance checks (separated from N1/N2 test_a01_a14.py)."""

from __future__ import annotations

import os
import platform

import pytest
from src.doctor import CheckStatus
from src.n3_probe import N3ProbeReport, run_n3_probe


def require_n3_linux_env_or_skip() -> N3ProbeReport:
    """Run N3 probe and skip honestly on non-N3 dev hosts unless GROKBOT_N3_STRICT=1."""
    host_os = platform.system()
    if host_os != "Linux":
        pytest.skip(
            f"PENDING_N3_LINUX_ENV: Host OS is {host_os}; "
            "Linux kernel netns/iptables and local LLM required."
        )

    report = run_n3_probe()
    # Never skip genuine CheckStatus.FAIL results (e.g., active egress failure or bad origin).
    if any(c.status == CheckStatus.FAIL for c in report.checks):
        return report

    strict = os.environ.get("GROKBOT_N3_STRICT", "").strip().lower() in {"1", "true", "yes"}
    if not strict and report.overall_status != "READY":
        notes = "; ".join(report.evidence_notes) if report.evidence_notes else "non-N3 Linux host"
        pytest.skip(f"{report.overall_status}: {notes}")

    return report


@pytest.mark.acceptance
@pytest.mark.n3
def test_a11_linux_kernel_netns_and_local_llm_n3() -> None:
    report = require_n3_linux_env_or_skip()
    assert report.linux_os_ready is True
    assert report.network_isolation_ready is True
    assert report.overall_status == "READY"
