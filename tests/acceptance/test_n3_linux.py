"""Linux-only N3 acceptance checks (separated from N1/N2 test_a01_a14.py)."""

from __future__ import annotations

import platform

import pytest
from src.n3_probe import run_n3_probe


@pytest.mark.acceptance
@pytest.mark.n3
@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="PENDING_N3_LINUX_ENV: Linux kernel netns/iptables and local LLM required.",
)
def test_a11_linux_kernel_netns_and_local_llm_n3() -> None:
    report = run_n3_probe()
    assert report.linux_os_ready is True
    assert report.network_isolation_ready is True
    assert report.overall_status == "READY"
