"""N1 unit tests for src/n3_probe.py honesty and injectable Linux/A11/LLM/Desktop checks."""

from __future__ import annotations

import json
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from src.doctor import CheckStatus
from src.n3_probe import main, run_n3_probe


@pytest.mark.n1
def test_n3_probe_macos_honestly_reports_pending_n3_linux_env(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = run_n3_probe(system_name="Darwin")
    assert report.overall_status == "PENDING_N3_LINUX_ENV"
    assert report.linux_os_ready is False
    assert report.network_isolation_ready is False
    assert report.local_llm_ready is False
    assert report.desktop_ready is False
    assert any("macOS" in note or "NEVER" in note for note in report.evidence_notes)

    if platform.system() != "Linux":
        rc = main(["--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["overall_status"] == "PENDING_N3_LINUX_ENV"

        rc_strict = main(["--strict"])
        assert rc_strict == 1


@pytest.mark.n1
def test_n3_probe_rejects_external_llm_origin_and_cli_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = run_n3_probe(
        system_name="Linux",
        llm_origin="https://api.openai.com",
    )
    llm_check = next(c for c in report.checks if c.name == "local_llm_n3")
    assert llm_check.status == CheckStatus.FAIL
    assert report.overall_status == "PENDING_N3_LINUX_ENV"

    rc = main(["--json", "--llm-origin", "https://api.openai.com"])
    assert rc == 2
    parsed = json.loads(capsys.readouterr().out)
    assert any(c["status"] == "fail" for c in parsed["checks"])


@pytest.mark.n1
def test_n3_probe_injectable_linux_netns_llm_and_desktop_states(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Debian GNU/Linux"\n', encoding="utf-8")

    # Linux with netns + nftables drop + no LLM yet -> PENDING_LOCAL_LLM
    pending_llm = run_n3_probe(
        system_name="Linux",
        os_release_path=os_release,
        which_fn=lambda tool: f"/usr/sbin/{tool}" if tool in ("ip", "nft") else None,
        run_cmd=lambda cmd: (0, "grokbot-isolated", "") if "netns" in cmd else (0, "drop", ""),
        probe_external_fn=lambda: False,
        env={},
        import_checker=lambda _: False,
    )
    assert pending_llm.linux_os_ready is True
    assert pending_llm.network_isolation_ready is True
    assert pending_llm.local_llm_ready is False
    assert pending_llm.overall_status == "PENDING_LOCAL_LLM"

    # Full Linux + netns + reachable loopback LLM + X11 AT-SPI -> READY
    ready = run_n3_probe(
        system_name="Linux",
        os_release_path=os_release,
        llm_origin="http://127.0.0.1:8080",
        which_fn=lambda tool: (
            f"/usr/bin/{tool}" if tool in ("ip", "iptables", "llama-server") else None
        ),
        run_cmd=lambda cmd: (
            (0, "grokbot-isolated", "") if "netns" in cmd else (0, "-A OUTPUT -j DROP", "")
        ),
        probe_external_fn=lambda: False,
        http_probe_fn=lambda origin: (True, 200, f"ok {origin}"),
        env={"DISPLAY": ":0", "AT_SPI_BUS_ADDRESS": "unix:path=/tmp/atspi"},
        import_checker=lambda mod: mod == "gi",
    )
    assert ready.overall_status == "READY"
    assert ready.linux_os_ready is True
    assert ready.network_isolation_ready is True
    assert ready.local_llm_ready is True
    assert ready.desktop_ready is True


@pytest.mark.n1
def test_n3_probe_egress_failure_marks_fail(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Ubuntu"\n', encoding="utf-8")

    failed = run_n3_probe(
        system_name="Linux",
        os_release_path=os_release,
        which_fn=lambda tool: f"/usr/sbin/{tool}" if tool in ("ip", "iptables") else None,
        run_cmd=lambda cmd: (0, "ns1", "") if "netns" in cmd else (0, "-A OUTPUT -j DROP", ""),
        probe_external_fn=lambda: True,
    )
    net_check = next(c for c in failed.checks if c.name == "network_isolation_a11")
    assert net_check.status == CheckStatus.FAIL
    assert failed.network_isolation_ready is False


@pytest.mark.n1
def test_n3_probe_non_2xx_http_404_server_returns_clean_report() -> None:
    class _Handler404(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler404)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        report = run_n3_probe(
            system_name="Linux",
            llm_origin=f"http://127.0.0.1:{port}",
            which_fn=lambda _: None,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert report.local_llm_ready is False
    llm_check = next(c for c in report.checks if c.name == "local_llm_n3")
    assert llm_check.status == CheckStatus.PENDING_N3_LINUX_ENV
    assert llm_check.detail["endpoint_reachable"] is False
    assert llm_check.detail["endpoint_status"] == 404
    assert "HTTP 404" in str(llm_check.detail["probe_note"])


@pytest.mark.n1
def test_deploy_n3_probe_cli_json_and_strict_honesty(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from deploy.n3_probe import main as deploy_n3_main

    rc = deploy_n3_main(["--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["host_os"] == platform.system()
    assert payload["status"] == payload["overall_status"]
    assert isinstance(payload["egress_blocked"], bool)

    if platform.system() != "Linux":
        assert payload["status"] == "PENDING_N3_LINUX_ENV"
        assert payload["overall_status"] == "PENDING_N3_LINUX_ENV"
        assert payload["egress_blocked"] is False
        assert deploy_n3_main(["--strict"]) == 1
