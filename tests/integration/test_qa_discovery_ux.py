"""Integration tests for live Playwright control discovery, modal focus, and UX telemetry."""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from src.qa.discovery import (
    probe_control_state_transition,
    probe_modal_focus_cycle,
    run_live_discovery,
)
from src.qa.isolation import IsolatedLabServer, StrictPlaywrightSession, alloc_ephemeral_port
from src.qa.ux_metrics import (
    PNG_MAGIC,
    UxFlowMetrics,
    capture_screenshot_checkpoint,
    check_composer_single_row,
    check_local_remote_indicator,
    measure_ux_action,
    save_ux_metrics,
)

pytestmark = pytest.mark.n2

_REPO_ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def _mock_app_server(
    html_body: str,
    *,
    post_counts: dict[str, int] | None = None,
) -> Iterator[str]:
    port = alloc_ephemeral_port()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path_only = self.path.split("?", 1)[0]
            if path_only == "/health":
                payload = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            payload = html_body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            path_only = self.path.split("?", 1)[0]
            if post_counts is not None:
                post_counts[path_only] = post_counts.get(path_only, 0) + 1
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


async def test_live_discovery_against_isolated_studio_emits_coverage_and_screenshots(
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "studio_discovery"
    result = await run_live_discovery(
        output_dir=out_dir,
        campaign_id="int-studio-discovery",
        repo_root=_REPO_ROOT,
        allow_mutation=False,
        capture_screenshots=True,
    )
    cov = result.coverage
    assert result.coverage_path is not None
    cov_path = Path(result.coverage_path)
    assert cov_path.is_file()

    assert cov.total_controls > 50
    assert cov.covered_count > 10
    assert (
        cov.covered_count
        + cov.blocked_count
        + cov.pending_count
        + cov.out_of_scope_count
        == cov.total_controls
    )
    for item in cov.items:
        if item.coverage_status != "covered":
            assert item.blocked_reason and item.blocked_reason.strip()
        for bad_tok in (");", "<path", "=>", "return "):
            assert bad_tok not in item.accessible_name, (
                f"Leaked JSX/TS syntax {bad_tok!r} in {item.control_id}: {item.accessible_name!r}"
            )

    assert result.console_errors == []
    assert result.page_errors == []
    assert result.external_requests == []

    assert len(result.screenshots) >= 2
    for shot in result.screenshots:
        png_path = Path(shot.path)
        assert png_path.is_file()
        raw = png_path.read_bytes()
        assert raw.startswith(PNG_MAGIC)
        assert len(raw) > 512

    assert result.local_remote_indicator_visible is True
    assert "top_level_workspace" in result.local_remote_location
    assert not any("FullScreenTakeoverModal" in d for d in result.focus_defects)


async def test_live_discovery_detects_silent_noop_and_unexplained_disabled_controls(
    tmp_path: Path,
) -> None:
    html = """<!doctype html>
<html lang="en" data-theme="light">
<head><title>Mock Studio</title></head>
<body>
  <div id="root">
    <textarea aria-label="Message composer"></textarea>
    <button id="silent-noop-btn">Deploy</button>
    <button id="disabled-unexplained-btn" disabled>Locked</button>
    <button id="working-toggle-btn" aria-pressed="false"
      onclick="this.setAttribute('aria-pressed', 'true')">ToggleMode</button>
  </div>
</body>
</html>"""
    with _mock_app_server(html) as base_url:
        out_dir = tmp_path / "mock_discovery"
        result = await run_live_discovery(
            base_url=base_url,
            output_dir=out_dir,
            campaign_id="int-mock-noop",
            repo_root=_REPO_ROOT,
        )

    items_by_name = {item.accessible_name: item for item in result.coverage.items}
    assert "Deploy" in items_by_name
    deploy_item = items_by_name["Deploy"]
    assert deploy_item.coverage_status == "blocked"
    assert deploy_item.post_state == "silent_noop"
    assert deploy_item.blocked_reason and "no-op" in deploy_item.blocked_reason.lower()
    assert "Deploy" in result.silent_noop_controls

    locked_item = items_by_name["Locked"]
    assert locked_item.coverage_status == "blocked"
    assert locked_item.blocked_reason and "explanation" in locked_item.blocked_reason.lower()

    toggle_item = items_by_name["ToggleMode"]
    assert toggle_item.coverage_status == "covered"


async def test_modal_focus_cycle_detects_body_fallback_and_passes_settings_modal(
    tmp_path: Path,
) -> None:
    broken_modal_html = """<!doctype html>
<html><body>
  <button id="open-no-trap" onclick="
    const d = document.getElementById('no-trap-dlg');
    d.style.display = 'block';
    document.getElementById('no-trap-btn').focus();
  ">OpenNoTrap</button>
  <button id="open-body-fallback" onclick="
    const d = document.getElementById('body-dlg');
    d.style.display = 'block';
    document.getElementById('body-dlg-btn').focus();
  ">OpenBodyFallback</button>
  <div id="no-trap-dlg" role="dialog" aria-modal="true" style="display:none">
    <button id="no-trap-btn">InsideNoTrap</button>
  </div>
  <div id="body-dlg" role="dialog" aria-modal="true" style="display:none">
    <button id="body-dlg-btn">InsideTrapped</button>
  </div>
  <script>
    document.addEventListener('keydown', (e) => {
      const bodyDlg = document.getElementById('body-dlg');
      if (bodyDlg.style.display === 'block' && e.key === 'Tab') {
        e.preventDefault();
        document.getElementById('body-dlg-btn').focus();
      }
      if (e.key === 'Escape') {
        document.getElementById('no-trap-dlg').style.display = 'none';
        bodyDlg.style.display = 'none';
        document.body.focus();
      }
    });
  </script>
</body></html>"""
    with _mock_app_server(broken_modal_html) as mock_url:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_broken") as session:
            await session.page.goto(f"{mock_url}/app", wait_until="domcontentloaded")
            ok_trap, reason_trap = await probe_modal_focus_cycle(session.page, "#open-no-trap")
            assert ok_trap is False
            assert reason_trap is not None and "escaped modal focus trap" in reason_trap

            ok_body, reason_body = await probe_modal_focus_cycle(
                session.page, "#open-body-fallback"
            )
            assert ok_body is False
            assert reason_body is not None and "BODY" in reason_body

            status, _, post_st, blk_reason = await probe_control_state_transition(
                session.page, "#open-body-fallback"
            )
            assert status == "covered"
            assert post_st != "silent_noop"
            assert blk_reason is None

    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            await session.page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await session.page.locator('aside button[aria-label="Settings"]').wait_for(
                state="visible", timeout=15000
            )
            ok, reason = await probe_modal_focus_cycle(
                session.page, 'aside button[aria-label="Settings"]'
            )
            assert ok is True, f"Unexpected Settings modal focus defect: {reason}"
            assert reason is None


async def test_ux_metrics_measurement_layout_and_checkpoint_on_isolated_studio(
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "ux_out"
    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            page = session.page
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )

            async def _open_settings() -> bool:
                await page.locator('aside button[aria-label="Settings"]').click()
                await page.locator('[role="dialog"][aria-modal="true"]').wait_for(
                    state="visible", timeout=5000
                )
                return True

            async def _probe_dialog() -> bool:
                return await page.locator('[role="dialog"][aria-modal="true"]').is_visible()

            opened, timing = await measure_ux_action(
                _open_settings,
                actions_to_reach=1,
                ttfp_probe=_probe_dialog,
                cancel_available=True,
            )
            assert opened is True
            assert timing.ttfp_ms is not None
            assert 0.0 <= timing.ttfp_ms <= timing.completion_ms

            await page.keyboard.press("Escape")
            await page.locator('[role="dialog"][aria-modal="true"]').wait_for(
                state="hidden", timeout=5000
            )

            intact_closed, _ = await check_composer_single_row(page)
            assert intact_closed is True

            lr_visible, lr_location = await check_local_remote_indicator(page)
            assert lr_visible is True
            assert "top_level_workspace" in lr_location

            shot = await capture_screenshot_checkpoint(
                page,
                output_dir=out_dir,
                case_id="CB-00",
                label="studio_ux_check",
                repo_root=_REPO_ROOT,
            )
            assert Path(shot.path).read_bytes().startswith(PNG_MAGIC)

            metrics_path = save_ux_metrics(
                [
                    UxFlowMetrics(
                        case_id="CB-00",
                        run_id="int-ux-1",
                        actions_to_reach=timing.actions_to_reach,
                        ttfp_ms=timing.ttfp_ms,
                        completion_ms=timing.completion_ms,
                        cancel_available=timing.cancel_available,
                        local_remote_indicator_visible=lr_visible,
                        local_remote_location=lr_location,
                        composer_layout_intact=intact_closed,
                        screenshots=[shot],
                    )
                ],
                out_dir / "ux_metrics.json",
                campaign_id="int-ux",
                repo_root=_REPO_ROOT,
            )
            payload = json.loads(metrics_path.read_text(encoding="utf-8"))
            assert payload["campaign_id"] == "int-ux"
            assert len(payload["flows"]) == 1
            assert len(payload["screenshots"]) == 1


async def test_probe_self_disabling_noop_and_mutation_gate(tmp_path: Path) -> None:
    html = """<!doctype html>
<html><body>
  <div id="root">
    <button id="self-disable-btn" onclick="this.disabled=true">SelfDisable</button>
    <button id="aria-disable-btn"
      onclick="this.setAttribute('aria-disabled','true')">AriaDisable</button>
    <button id="effect-disable-btn"
      onclick="this.disabled=true; document.getElementById('status').textContent='Saved';">
      EffectDisable
    </button>
    <div id="status"></div>
    <button id="create-bot-btn" onclick="fetch('/api/create', {method:'POST'})">Create bot</button>
    <button id="delete-bot-btn" onclick="fetch('/api/delete', {method:'POST'})">Delete bot</button>
    <button id="send-msg-btn" onclick="fetch('/api/send', {method:'POST'})">Send message</button>
    <button id="save-chg-btn" onclick="fetch('/api/save', {method:'POST'})">Save changes</button>
  </div>
</body></html>"""
    post_counts: dict[str, int] = {}
    with _mock_app_server(html, post_counts=post_counts) as mock_url:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_self_dis") as session:
            await session.page.goto(f"{mock_url}/app", wait_until="domcontentloaded")

            for sel in ("#self-disable-btn", "#aria-disable-btn"):
                st, init_st, post_st, reason = await probe_control_state_transition(
                    session.page, sel
                )
                assert st == "blocked"
                assert init_st == "enabled"
                assert post_st == "self_disabled_unexplained"
                assert reason and "without explanation" in reason

            st_eff, _, _, _ = await probe_control_state_transition(
                session.page, "#effect-disable-btn"
            )
            assert st_eff == "covered"

            for sel in ("#create-bot-btn", "#delete-bot-btn", "#send-msg-btn", "#save-chg-btn"):
                st_m, _, _, reason_m = await probe_control_state_transition(
                    session.page, sel, allow_mutation=False
                )
                assert st_m == "out_of_scope"
                assert reason_m and "allow_mutation=False" in reason_m
            assert post_counts == {}

            for sel in ("#create-bot-btn", "#send-msg-btn", "#save-chg-btn"):
                st_ok, _, _, _ = await probe_control_state_transition(
                    session.page, sel, allow_mutation=True
                )
                assert st_ok == "covered"
            assert post_counts == {"/api/create": 1, "/api/send": 1, "/api/save": 1}


async def test_modal_focus_cycle_catches_5_button_untrapped_modal(tmp_path: Path) -> None:
    html = """<!doctype html>
<html><body>
  <button id="open-5-btn" onclick="
    const d = document.getElementById('dlg-5');
    d.style.display = 'block';
    document.getElementById('d-btn-1').focus();
  ">OpenFive</button>
  <button id="bg-btn">BackgroundButton</button>
  <div id="dlg-5" role="dialog" aria-modal="true" style="display:none">
    <button id="d-btn-1">One</button>
    <button id="d-btn-2">Two</button>
    <button id="d-btn-3">Three</button>
    <button id="d-btn-4">Four</button>
    <button id="d-btn-5">Five</button>
  </div>
  <script>
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.getElementById('dlg-5').style.display = 'none';
      }
    });
  </script>
</body></html>"""
    with _mock_app_server(html) as mock_url:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_modal5") as session:
            await session.page.goto(f"{mock_url}/app", wait_until="domcontentloaded")
            ok, reason = await probe_modal_focus_cycle(session.page, "#open-5-btn")
            assert ok is False
            assert reason is not None and "escaped modal focus trap" in reason


async def test_ux_indicator_and_composer_wrap_without_attach_button(tmp_path: Path) -> None:
    false_cloud_html = """<!doctype html>
<html><body>
  <header><span>Chat</span></header>
  <aside><button>Cloud Assistant</button></aside>
  <div style="width:160px; display:flex; flex-wrap:wrap;">
    <select aria-label="Turn model override" style="width:140px;">
      <option>Model: Default</option>
    </select>
    <button aria-label="Send message" style="width:80px;">Send</button>
  </div>
</body></html>"""
    with _mock_app_server(false_cloud_html) as mock_url:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_ux_tight") as session:
            await session.page.goto(f"{mock_url}/app", wait_until="domcontentloaded")
            vis, loc = await check_local_remote_indicator(session.page)
            assert vis is False
            assert loc == "not_visible_top_level"

            intact, reason = await check_composer_single_row(session.page)
            assert intact is False
            assert "wrapped" in reason.lower()

    badge_html = """<!doctype html>
<html><body>
  <header><span data-testid="runtime-badge">Local Runtime</span></header>
</body></html>"""
    with _mock_app_server(badge_html) as mock_url:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_ux_badge") as session:
            await session.page.goto(f"{mock_url}/app", wait_until="domcontentloaded")
            vis2, loc2 = await check_local_remote_indicator(session.page)
            assert vis2 is True
            assert "Local Runtime" in loc2
