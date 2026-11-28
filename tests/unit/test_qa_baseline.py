"""Unit tests for M1 QA models, isolation, baseline surface checks, and CLI."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.testclient import TestClient
from pydantic import ValidationError
from src.contracts.common import utc_now
from src.factory.policy import PolicyGuard
from src.qa.baseline import (
    _frontend_dist_lock,
    collect_frontend_dist_assets,
    extract_app_assets_and_markers,
    run_baseline,
    verify_app_surface_http,
)
from src.qa.cli import build_parser, dispatch_command, main
from src.qa.isolation import (
    LIVE_FORBIDDEN_PORTS,
    IsolationBoundaryError,
    LogCursor,
    alloc_ephemeral_port,
    assert_allowed_grokbot_target,
    assert_not_live_target,
    assert_safe_mutation_path,
    read_sanitized_logs,
    summarize_active_logs,
)
from src.qa.models import (
    BaselineReport,
    CampaignState,
    CandidateManifest,
    ControlInventoryItem,
    CoverageReport,
    QAFailureItem,
    ReferenceBehaviorCard,
    RunRecord,
)
from src.storage.redaction import contains_unredacted_secret_strict
from src.web.app import _render_studio_app_html, create_app


def _make_synthetic_dist(dist_dir: Path) -> tuple[str, str]:
    assets_dir = dist_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    js_bytes = b"console.log('react studio boot');\n"
    css_bytes = b"body { color: #0f172a; }\n"
    (assets_dir / "index-TEST1234.js").write_bytes(js_bytes)
    (assets_dir / "index-TEST5678.css").write_bytes(css_bytes)
    index_html = (
        "<!doctype html>\n"
        '<html lang="en" data-theme="light">\n'
        "  <head>\n"
        '    <meta charset="UTF-8" />\n'
        "    <title>Grok Bot — ControlBot Studio</title>\n"
        '    <script type="module" crossorigin src="/assets/index-TEST1234.js"></script>\n'
        '    <link rel="stylesheet" crossorigin href="/assets/index-TEST5678.css">\n'
        "  </head>\n"
        "  <body>\n"
        '    <div id="root"></div>\n'
        "  </body>\n"
        "</html>\n"
    )
    (dist_dir / "index.html").write_text(index_html, encoding="utf-8")
    return (
        hashlib.sha256(js_bytes).hexdigest(),
        hashlib.sha256(css_bytes).hexdigest(),
    )


@pytest.mark.n1
def test_models_round_trip_and_strict_validation() -> None:
    now = utc_now()
    baseline = BaselineReport(
        campaign_id="qa-test-001",
        generated_at=now,
        repo_sha="abc1234",
        surface_verified=True,
        served_surface="react",
        asset_hashes={"/assets/index-a.js": "deadbeef"},
        backend_mode="emulated",
        runtime_mode="live_runtime",
        n3_status="PENDING_N3_LINUX_ENV",
        overall_passed=True,
        exit_code=0,
    )
    assert BaselineReport.model_validate_json(baseline.model_dump_json()) == baseline

    run_rec = RunRecord(
        campaign_id="qa-test-001",
        case_id="CB-00",
        run_id="run-1",
        base_sha="abc1234",
        lane="local_deterministic",
        backend_mode="emulated",
        started_at=now,
        finished_at=now,
        duration_ms=12.5,
        passed=True,
    )
    assert RunRecord.model_validate_json(run_rec.model_dump_json()) == run_rec

    item = QAFailureItem(
        item_id="item-1",
        dedup_key="CB-00:web:http_500",
        case_id="CB-00",
        subsystem="web",
        normalized_signature="http_500",
        severity="P1",
        summary="500 error",
        first_seen_sha="abc1234",
        last_seen_sha="abc1234",
        environment_lane="local_deterministic",
    )
    assert QAFailureItem.model_validate_json(item.model_dump_json()) == item

    state = CampaignState(campaign_id="qa-test-001", base_sha="abc1234", output_dir="/tmp/qa")
    assert CampaignState.model_validate_json(state.model_dump_json()) == state

    cand = CandidateManifest(
        candidate_id="cand-1",
        item_id="item-1",
        campaign_id="qa-test-001",
        base_sha="abc1234",
        branch_name="qa/cand-1",
        rerun_command="pytest tests/unit/test_qa_baseline.py",
        baseline_passed=False,
        candidate_passed=True,
    )
    assert CandidateManifest.model_validate_json(cand.model_dump_json()) == cand

    ctrl = ControlInventoryItem(
        control_id="roster:app:button:new",
        module="roster",
        route="/app",
        role="button",
        accessible_name="New bot",
        selector='button[aria-label="New bot"]',
        initial_state="enabled",
    )
    cov = CoverageReport(
        campaign_id="qa-test-001",
        repo_sha="abc1234",
        total_controls=1,
        covered_count=0,
        blocked_count=0,
        pending_count=1,
        out_of_scope_count=0,
        items=[ctrl],
    )
    assert CoverageReport.model_validate_json(cov.model_dump_json()) == cov

    card = ReferenceBehaviorCard(
        card_id="card-1",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
    )
    assert ReferenceBehaviorCard.model_validate_json(card.model_dump_json()) == card

    with pytest.raises(ValidationError):
        ReferenceBehaviorCard.model_validate(
            {
                "card_id": "card-bad",
                "case_id": "CB-01",
                "source": "grok_bot_app",
                "status": "observed",
                "bot_used": "other_bot",
            }
        )

    with pytest.raises(ValidationError):
        BaselineReport(
            campaign_id="qa-test-001",
            repo_sha="abc1234",
            surface_verified=True,
            served_surface="react",
            backend_mode="emulated",
            runtime_mode="live_runtime",
            n3_status="READY",
            unexpected_extra="nope",  # type: ignore[call-arg]
        )


@pytest.mark.n1
def test_asset_hash_verification_passes_for_rendered_react_html(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    expected_js, expected_css = _make_synthetic_dist(dist_dir)
    raw_html = (dist_dir / "index.html").read_text(encoding="utf-8")
    rendered_html = _render_studio_app_html(raw_html, dist_dir / "assets")

    inspection = extract_app_assets_and_markers(rendered_html)
    assert inspection.has_root_div is True
    assert inspection.has_legacy_markers is False
    assert "/assets/index-TEST1234.js" in inspection.asset_urls
    assert "/assets/index-TEST5678.css" in inspection.asset_urls

    app = FastAPI()

    @app.get("/app")
    @app.get("/app/{subpath:path}")
    def serve_app(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(rendered_html)

    @app.get("/assets/{name}")
    def serve_asset(name: str) -> PlainTextResponse:
        return PlainTextResponse((dist_dir / "assets" / name).read_text(encoding="utf-8"))

    with TestClient(app) as client:
        res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert res.surface_verified is True
    assert res.served_surface == "react"
    assert res.boot_errors == []
    assert res.asset_hashes["/assets/index-TEST1234.js"] == expected_js
    assert res.asset_hashes["/assets/index-TEST5678.css"] == expected_css


@pytest.mark.n1
def test_asset_hash_verification_fails_on_tampered_or_missing_asset(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    _make_synthetic_dist(dist_dir)
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )

    dist_hashes, dist_errs = collect_frontend_dist_assets(dist_dir)
    assert dist_errs == []
    assert len(dist_hashes) == 2

    app = FastAPI()

    @app.get("/app")
    @app.get("/app/{subpath:path}")
    def serve_app(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(rendered_html)

    @app.get("/assets/{name}")
    def serve_asset(name: str) -> PlainTextResponse:
        if name.endswith(".js"):
            return PlainTextResponse("console.log('tampered');\n")
        return PlainTextResponse("missing", status_code=404)

    with TestClient(app) as client:
        res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert res.surface_verified is False
    assert res.served_surface == "react"
    assert "/assets/index-TEST1234.js" in res.asset_hash_mismatches
    assert any("mismatch" in err.lower() for err in res.boot_errors)
    assert any("404" in err for err in res.boot_errors)


@pytest.mark.n1
def test_legacy_studio_html_fallback_detected_and_fails_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.web.app as web_app

    missing_dist = tmp_path / "missing_dist"
    monkeypatch.setattr(web_app, "_FRONTEND_DIST_DIR", missing_dist)
    monkeypatch.setenv("HOME", str(tmp_path / "fake_home"))
    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "lab_profiles"))
    app = create_app(db_path=tmp_path / "controlbot.sqlite3")

    with TestClient(app) as client:
        raw_resp = client.get("/app")
        assert raw_resp.status_code == 200
        res = verify_app_surface_http(client, dist_dir=missing_dist)

    assert res.served_surface == "legacy_fallback"
    assert res.ui_variant == "studio_legacy"
    assert res.surface_verified is False
    assert any("studio.html" in err for err in res.boot_errors)


@pytest.mark.n1
def test_secret_redaction_in_baseline_report_and_log_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    rotated_line = json.dumps(
        {
            "ts": "2026-11-27T05:00:00Z",
            "source": "backend",
            "kind": "http_500",
            "message": "Authorization: Bearer sk-secret-999",
            "url": "http://127.0.0.1:8000/app?token=mut_tok_abc",
        }
    )
    active_line = json.dumps(
        {
            "ts": "2026-11-27T05:01:00Z",
            "source": "frontend",
            "kind": "console_error",
            "message": "failed apiKey=secret_val_xyz",
            "apiKey": "secret_val_xyz",
        }
    )
    rotated_path = logs_dir / "failures.jsonl.1"
    active_path = logs_dir / "failures.jsonl"
    rotated_path.write_text(rotated_line + "\n", encoding="utf-8")
    rot_stat = rotated_path.stat()
    active_path.write_text(active_line + "\n", encoding="utf-8")

    cursor = LogCursor("failures.jsonl", (rot_stat.st_dev, rot_stat.st_ino), 0)
    records, next_cursors = read_sanitized_logs(
        logs_dir,
        cursors={"failures.jsonl": cursor},
    )
    assert len(records["failures.jsonl"]) == 2
    assert next_cursors["failures.jsonl"].byte_offset > 0

    summary = summarize_active_logs(logs_dir)
    assert summary["counts_by_file"]["failures.jsonl"] == 1
    assert not contains_unredacted_secret_strict(summary)

    fake_repo = tmp_path / "fake_repo"
    dist_dir = fake_repo / "frontend" / "dist"
    _make_synthetic_dist(dist_dir)
    subprocess.run(["git", "init", str(fake_repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(fake_repo), "config", "user.name", "QA Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(fake_repo), "config", "user.email", "qa@example.local"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(fake_repo), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )

    class _FakeResp:
        def __init__(self, status_code: int, text: str = "", content: bytes = b"") -> None:
            self.status_code = status_code
            self.text = text
            self.content = content or text.encode("utf-8")

        def json(self) -> Any:
            return json.loads(self.text)

    class _FakeClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def get(self, path: str, params: dict[str, str] | None = None) -> _FakeResp:
            del params
            if path.startswith("/app"):
                return _FakeResp(200, text=rendered_html)
            if path == "/assets/index-TEST1234.js":
                js_bytes = (dist_dir / "assets" / "index-TEST1234.js").read_bytes()
                return _FakeResp(200, content=js_bytes)
            if path == "/assets/index-TEST5678.css":
                css_bytes = (dist_dir / "assets" / "index-TEST5678.css").read_bytes()
                return _FakeResp(200, content=css_bytes)
            if path == "/api/system/info":
                return _FakeResp(
                    200,
                    text=json.dumps({"backend_mode": "emulated", "runtime_mode": "live_runtime"}),
                )
            if path == "/api/v1/bots":
                return _FakeResp(200, text=json.dumps({"bots": []}))
            return _FakeResp(404)

    import httpx

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    out_dir = tmp_path / "campaign"
    report = run_baseline(
        repo_root=tmp_path / "fake_repo",
        output_dir=out_dir,
        target_url="http://127.0.0.1:9999/app?token=web_secret_123",
        token="web_secret_123",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=logs_dir,
        campaign_id="qa-redact-test",
    )
    assert report.overall_passed is True
    rep_rc = main(
        ["report", "--campaign-dir", str(out_dir), "--repo-root", str(tmp_path / "fake_repo")]
    )
    assert rep_rc == 0

    for fname in ("baseline.json", "BASELINE.md", "campaign.json", "daily_report.md", "HANDOFF.md"):
        text = (out_dir / fname).read_text(encoding="utf-8")
        for secret in ("sk-secret-999", "mut_tok_abc", "secret_val_xyz", "web_secret_123"):
            assert secret not in text

    baseline_obj = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert contains_unredacted_secret_strict(baseline_obj) is False


@pytest.mark.n1
def test_isolation_boundary_error_on_forbidden_paths_and_ports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for port in LIVE_FORBIDDEN_PORTS:
        with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
            assert_not_live_target(f"http://127.0.0.1:{port}", allow_readonly=False)
        assert_not_live_target(f"http://127.0.0.1:{port}", allow_readonly=True)

    for bad_path in (
        repo_root / "var" / "controlbot.sqlite3",
        repo_root / "var" / "controlbot_workspace.sqlite3",
        repo_root / "var" / "logs",
        tmp_path / ("." + "grokbot_profiles"),
        tmp_path / "browser_profiles",
        Path("/home/user/.config/Grok Bot"),
    ):
        with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
            assert_safe_mutation_path(bad_path, repo_root=repo_root)

    env_key = "GROKBOT_" + "DB_PATH"
    active_db = tmp_path / "custom_active.sqlite3"
    monkeypatch.setenv(env_key, str(active_db))
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        assert_safe_mutation_path(active_db, repo_root=repo_root)
    assert os.environ[env_key] == str(active_db)

    for _ in range(10):
        assert alloc_ephemeral_port() not in LIVE_FORBIDDEN_PORTS

    assert assert_allowed_grokbot_target("main") == "main"
    assert assert_allowed_grokbot_target("test") == "test"
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        assert_allowed_grokbot_target("other_private_bot")

    PolicyGuard().check_candidate_paths(
        [
            "src/qa/__init__.py",
            "src/qa/models.py",
            "src/qa/isolation.py",
            "src/qa/baseline.py",
            "src/qa/cli.py",
            "src/qa/__main__.py",
        ]
    )


@pytest.mark.n1
def test_cli_m1_implemented_and_m2_plus_dispatched(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "qa@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    (repo_dir / "README.md").write_text("# test\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True, capture_output=True
    )
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    camp_dir = tmp_path / "camp_m1"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-cli-test",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        catalog_hash="deadbeef",
        criteria_hash="cafebabe",
        limits={"max_parallel_repairers": 2, "max_attempts_per_item": 2},
        attempts={},
        artifacts={},
        output_dir=str(camp_dir),
    )
    (camp_dir / "campaign.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")

    assert main(["report", "--campaign-dir", str(camp_dir), "--json"]) == 0
    assert (camp_dir / "daily_report.md").is_file()
    assert (camp_dir / "HANDOFF.md").is_file()

    parser = build_parser()
    for argv in (
        ["scan", "--campaign-dir", str(camp_dir), "--repo-root", str(repo_dir)],
        ["repair", "--campaign-dir", str(camp_dir), "--repo-root", str(repo_dir)],
        ["resume", "--campaign-dir", str(camp_dir), "--repo-root", str(repo_dir)],
    ):
        parsed = parser.parse_args(argv)
        assert dispatch_command(parsed) == 0

    for missing_argv in (
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-1",
            "--repo-root",
            str(repo_dir),
        ],
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-1",
            "--repo-root",
            str(repo_dir),
        ],
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-1",
            "--repo-root",
            str(repo_dir),
        ],
    ):
        parsed = parser.parse_args(missing_argv)
        with pytest.raises(FileNotFoundError):
            dispatch_command(parsed)
        assert main(missing_argv) == 1


@pytest.mark.n1
def test_legacy_markers_rejected_even_when_root_div_title_and_loader_present(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    dist_dir = tmp_path / "dist"
    _make_synthetic_dist(dist_dir)
    react_rendered = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )
    legacy_html = (repo_root / "src" / "web" / "templates" / "studio.html").read_text(
        encoding="utf-8"
    )
    spoofed_legacy = legacy_html.replace(
        "<title>ControlBot Studio</title>",
        "<title>Grok Bot — ControlBot Studio</title>",
    ).replace(
        "<body>",
        '<body>\n<div id="root"></div>',
        1,
    )
    loader_snippet = (
        '<script>(function(){var css=["/assets/index-TEST5678.css"];'
        'var preloads=[];var js=["/assets/index-TEST1234.js"];})();</script>'
    )
    spoofed_with_loader = spoofed_legacy.replace("</head>", f"{loader_snippet}\n</head>", 1)

    app_root_spoof = FastAPI()

    @app_root_spoof.get("/app")
    @app_root_spoof.get("/app/{subpath:path}")
    def serve_spoofed(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(spoofed_with_loader)

    @app_root_spoof.get("/assets/{name}")
    def serve_asset_spoof(name: str) -> PlainTextResponse:
        return PlainTextResponse((dist_dir / "assets" / name).read_text(encoding="utf-8"))

    with TestClient(app_root_spoof) as client:
        res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert res.surface_verified is False
    assert res.served_surface == "legacy_fallback"
    assert res.ui_variant == "studio_legacy"
    assert res.inspection is not None
    assert res.inspection.has_legacy_markers is True
    assert res.boot_errors

    app_subpath_spoof = FastAPI()

    @app_subpath_spoof.get("/app")
    def serve_react_main() -> HTMLResponse:
        return HTMLResponse(react_rendered)

    @app_subpath_spoof.get("/app/{subpath:path}")
    def serve_legacy_subpath(subpath: str) -> HTMLResponse:
        del subpath
        return HTMLResponse(spoofed_with_loader)

    @app_subpath_spoof.get("/assets/{name}")
    def serve_asset_sub(name: str) -> PlainTextResponse:
        return PlainTextResponse((dist_dir / "assets" / name).read_text(encoding="utf-8"))

    with TestClient(app_subpath_spoof) as client:
        sub_res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert sub_res.surface_verified is False
    assert sub_res.served_surface == "legacy_fallback"
    assert any("qa-surface-check" in err for err in sub_res.boot_errors)


@pytest.mark.n1
def test_secondary_dist_assets_js_css_mjs_hashed_and_tampering_detected(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    _make_synthetic_dist(dist_dir)
    assets_dir = dist_dir / "assets"
    (assets_dir / "lazy-chunk-EXTRA.js").write_bytes(b"export const chunk = 'clean';\n")
    (assets_dir / "extra-panel.css").write_bytes(b".panel { display: flex; }\n")
    (assets_dir / "worker-extra.mjs").write_bytes(b"export default 42;\n")

    dist_hashes, dist_errs = collect_frontend_dist_assets(dist_dir)
    assert dist_errs == []
    assert set(dist_hashes) == {
        "/assets/index-TEST1234.js",
        "/assets/index-TEST5678.css",
        "/assets/lazy-chunk-EXTRA.js",
        "/assets/extra-panel.css",
        "/assets/worker-extra.mjs",
    }

    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        assets_dir,
    )

    app_clean = FastAPI()

    @app_clean.get("/app")
    @app_clean.get("/app/{subpath:path}")
    def serve_app_clean(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(rendered_html)

    @app_clean.get("/assets/{name}")
    def serve_asset_clean(name: str) -> PlainTextResponse:
        return PlainTextResponse((assets_dir / name).read_text(encoding="utf-8"))

    with TestClient(app_clean) as client:
        clean_res = verify_app_surface_http(client, dist_dir=dist_dir)
    assert clean_res.surface_verified is True
    assert clean_res.asset_hash_mismatches == {}

    app_tampered = FastAPI()

    @app_tampered.get("/app")
    @app_tampered.get("/app/{subpath:path}")
    def serve_app_tampered(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(rendered_html)

    @app_tampered.get("/assets/{name}")
    def serve_asset_tampered(name: str) -> PlainTextResponse:
        if name == "lazy-chunk-EXTRA.js":
            return PlainTextResponse("console.log('TAMPERED EXTRA CHUNK!');\n")
        if name == "worker-extra.mjs":
            return PlainTextResponse("export default 999;\n")
        return PlainTextResponse((assets_dir / name).read_text(encoding="utf-8"))

    with TestClient(app_tampered) as client:
        tampered_res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert tampered_res.surface_verified is False
    assert "/assets/lazy-chunk-EXTRA.js" in tampered_res.asset_hash_mismatches
    assert "/assets/worker-extra.mjs" in tampered_res.asset_hash_mismatches
    assert any("mismatch" in err.lower() for err in tampered_res.boot_errors)


@pytest.mark.n1
def test_read_sanitized_logs_preserves_incomplete_trailing_jsonl_line(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "failures.jsonl"

    first_line = '{"source":"a","kind":"b","message":"first"}\n'
    partial_prefix = '{"source":"a","kind":"b"'
    log_file.write_text(first_line + partial_prefix, encoding="utf-8")

    records1, cursors1 = read_sanitized_logs(logs_dir)
    assert len(records1["failures.jsonl"]) == 1
    assert records1["failures.jsonl"][0]["message"] == "first"
    assert cursors1["failures.jsonl"].byte_offset == len(first_line.encode("utf-8"))

    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(',"message":"second_completed"}\n')

    records2, cursors2 = read_sanitized_logs(logs_dir, cursors=cursors1)
    assert len(records2["failures.jsonl"]) == 1
    assert records2["failures.jsonl"][0]["message"] == "second_completed"
    assert cursors2["failures.jsonl"].byte_offset == log_file.stat().st_size


@pytest.mark.n1
def test_read_sanitized_logs_redacts_encoded_bearer_and_basic_in_query_params(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Bearer%20sk-urlenc-777&ok=1",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Bearer+sk-plus-888",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Basic%20dXNlcjpwYXNz",
        },
        {
            "source": "frontend",
            "kind": "console_error",
            "message": "GET http://127.0.0.1:8000/app?q=Bearer%20sk-msg-999 failed",
        },
    ]
    (logs_dir / "failures.jsonl").write_text(
        "\n".join(json.dumps(item) for item in lines) + "\n",
        encoding="utf-8",
    )

    records, _ = read_sanitized_logs(logs_dir)
    items = records["failures.jsonl"]
    assert len(items) == 4
    serialized = json.dumps(items)
    for secret in ("sk-urlenc-777", "sk-plus-888", "dXNlcjpwYXNz", "sk-msg-999"):
        assert secret not in serialized
    assert "[REDACTED]" in items[0]["url"]
    assert "[REDACTED]" in items[1]["url"]
    assert "[REDACTED]" in items[2]["url"]
    assert "[REDACTED]" in items[3]["message"]
    assert contains_unredacted_secret_strict(items) is False


@pytest.mark.n1
def test_isolation_guards_db_sidecars_and_var_root_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    env_key = "GROKBOT_" + "DB_PATH"
    active_db = tmp_path / "custom_db" / "live.sqlite3"
    monkeypatch.setenv(env_key, str(active_db))

    for suffix in ("", "-wal", "-shm", "-journal"):
        sidecar = Path(f"{active_db}{suffix}")
        with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
            assert_safe_mutation_path(sidecar, repo_root=repo_root)

    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        assert_safe_mutation_path(repo_root / "var", repo_root=repo_root)

    allowed_campaign = assert_safe_mutation_path(
        repo_root / "var" / "qa_campaigns" / "qa-safe-123",
        repo_root=repo_root,
    )
    assert allowed_campaign == (repo_root / "var" / "qa_campaigns" / "qa-safe-123").resolve()


@pytest.mark.n1
def test_run_baseline_blocks_no_isolated_lab_browser_against_live_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    out_dir = tmp_path / "camp_live_block"

    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        run_baseline(
            repo_root=repo_root,
            output_dir=out_dir,
            target_url="http://127.0.0.1:8000",
            build_frontend=False,
            skip_browser=False,
            use_isolated_lab=False,
        )

    rc = main(
        [
            "baseline",
            "--target-url",
            "http://127.0.0.1:8000",
            "--no-isolated-lab",
            "--no-build-frontend",
            "--output-dir",
            str(out_dir),
            "--json",
        ]
    )
    assert rc == 1

    # Read-only HTTP-only check (--skip-browser) against live port remains permitted.
    import src.qa.baseline as baseline_mod

    monkeypatch.setattr(
        baseline_mod,
        "probe_live_readonly",
        lambda *a, **kw: {"health_ok": False, "errors": []},
    )
    monkeypatch.setattr(baseline_mod, "summarize_active_logs", lambda *a, **kw: {"exists": False})
    monkeypatch.setattr(
        baseline_mod,
        "verify_app_surface_http",
        lambda *a, **kw: baseline_mod.SurfaceHttpCheckResult(
            served_surface="unreachable",
            ui_variant="unknown",
            surface_verified=False,
            boot_errors=["unreachable"],
        ),
    )
    ro_report = run_baseline(
        repo_root=repo_root,
        output_dir=tmp_path / "camp_ro_http",
        target_url="http://127.0.0.1:8000",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
    )
    assert ro_report.exit_code == 2


@pytest.mark.n1
def test_makefile_qa_baseline_uses_worktree_safe_git_common_dir_flock(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    makefile_text = (repo_root / "Makefile").read_text(encoding="utf-8")
    assert "git rev-parse --git-common-dir" in makefile_text
    assert 'flock "$$(git rev-parse --git-common-dir)/qa_frontend_build.lock"' in makefile_text

    main_repo = tmp_path / "main_repo"
    main_repo.mkdir()
    subprocess.run(["git", "init", str(main_repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.name", "QA Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.email", "qa@example.local"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(main_repo), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )

    wt_dir = tmp_path / "wt_checkout"
    subprocess.run(
        ["git", "-C", str(main_repo), "worktree", "add", "--detach", str(wt_dir), "HEAD"],
        check=True,
        capture_output=True,
    )
    try:
        assert (wt_dir / ".git").is_file()
        with _frontend_dist_lock(wt_dir, exclusive=True):
            assert (main_repo / ".git" / "qa_frontend_build.lock").is_file()
    finally:
        subprocess.run(
            ["git", "-C", str(main_repo), "worktree", "remove", "--force", str(wt_dir)],
            check=False,
            capture_output=True,
        )


@pytest.mark.n1
def test_read_sanitized_logs_redacts_base64_and_plus_tokens_without_suffix_leak(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Basic%20dXNlcj5wYXNz%2Bpart2%3D%3D&ok=hello+world",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Bearer%20tok%2Bmore&safe=yes",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Bearer+tok+more&safe=yes",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Bearer%2Btok%2Bmore&safe=yes",
        },
        {
            "source": "backend",
            "kind": "http_500",
            "url": "http://127.0.0.1:8000/app?q=Basic%2BdXNlcj5wYXNz%2Bpart2%3D%3D",
        },
        {
            "source": "frontend",
            "kind": "console_error",
            "message": "GET http://127.0.0.1:8000/app?q=Basic%20dXNlcj5wYXNz%2Bpart2%3D%3D failed",
        },
        {
            "source": "frontend",
            "kind": "console_error",
            "message": "GET http://127.0.0.1:8000/app?q=Bearer+tok+more failed",
        },
    ]
    (logs_dir / "failures.jsonl").write_text(
        "\n".join(json.dumps(item) for item in lines) + "\n",
        encoding="utf-8",
    )

    records, _ = read_sanitized_logs(logs_dir)
    items = records["failures.jsonl"]
    assert len(items) == len(lines)
    serialized = json.dumps(items)
    for leaked in ("dXNlcj5wYXNz", "part2", "tok", "more"):
        assert leaked not in serialized
    assert "ok=hello+world" in items[0]["url"]
    for item in items[:5]:
        assert "[REDACTED]" in item["url"]
    for item in items[5:]:
        assert "[REDACTED]" in item["message"]
    assert contains_unredacted_secret_strict(items) is False


@pytest.mark.n1
def test_verify_app_surface_http_rejects_unexpected_html_assets_not_in_dist(
    tmp_path: Path,
) -> None:
    dist_dir = tmp_path / "dist"
    _make_synthetic_dist(dist_dir)
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )
    injected_html = rendered_html.replace(
        "</head>",
        '<script src="/assets/injected-evil.js"></script>\n'
        '<link rel="stylesheet" href="/assets/injected-evil.css">\n'
        '<script type="module" src="/assets/injected-evil.mjs"></script>\n</head>',
        1,
    )

    app = FastAPI()

    @app.get("/app")
    @app.get("/app/{subpath:path}")
    def serve_app(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(injected_html)

    @app.get("/assets/{name}")
    def serve_asset(name: str) -> PlainTextResponse:
        disk = dist_dir / "assets" / name
        if disk.is_file():
            return PlainTextResponse(disk.read_text(encoding="utf-8"))
        return PlainTextResponse("// injected\n")

    with TestClient(app) as client:
        res = verify_app_surface_http(client, dist_dir=dist_dir)

    assert res.surface_verified is False
    assert res.served_surface == "react"
    for unexpected in ("injected-evil.js", "injected-evil.css", "injected-evil.mjs"):
        assert any(unexpected in err for err in res.boot_errors)


@pytest.mark.n1
def test_verify_app_surface_http_rejects_subpath_without_react_title_or_assets(
    tmp_path: Path,
) -> None:
    dist_dir = tmp_path / "dist"
    _make_synthetic_dist(dist_dir)
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )

    for subpath_html, expected_marker in (
        ("<html><body><div id='root'></div></body></html>", "root/title"),
        (
            "<html><head><title>Grok Bot — ControlBot Studio</title></head>"
            "<body><div id='root'></div></body></html>",
            "omits dist assets",
        ),
    ):
        app = FastAPI()

        @app.get("/app")
        def serve_root() -> HTMLResponse:
            return HTMLResponse(rendered_html)

        @app.get("/app/{subpath:path}")
        def serve_subpath(subpath: str, _body: str = subpath_html) -> HTMLResponse:
            del subpath
            return HTMLResponse(_body)

        @app.get("/assets/{name}")
        def serve_asset(name: str) -> PlainTextResponse:
            return PlainTextResponse((dist_dir / "assets" / name).read_text(encoding="utf-8"))

        with TestClient(app) as client:
            res = verify_app_surface_http(client, dist_dir=dist_dir)

        assert res.surface_verified is False
        assert any(expected_marker in err for err in res.boot_errors)


def _init_git_repo_with_dist(repo_dir: Path) -> Path:
    dist_dir = repo_dir / "frontend" / "dist"
    _make_synthetic_dist(dist_dir)
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "QA Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "qa@example.local"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )
    return dist_dir


@pytest.mark.n1
def test_run_baseline_unreachable_target_classifies_connect_errors_as_boot_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_repo = tmp_path / "repo_unreach"
    dist_dir = _init_git_repo_with_dist(fake_repo)
    dead_port = alloc_ephemeral_port()

    report = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_dead",
        target_url=f"http://127.0.0.1:{dead_port}",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert report.served_surface == "unreachable"
    assert report.surface_verified is False
    assert report.overall_passed is False
    assert report.exit_code == 2
    assert report.boot_errors
    assert report.functional_errors == []

    # Even if /app succeeds, a mid-check ConnectError/TimeoutException on /api/* is a boot error.
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )
    import httpx

    class _FlakyResp:
        def __init__(self, status_code: int, text: str = "", content: bytes = b"") -> None:
            self.status_code = status_code
            self.text = text
            self.content = content or text.encode("utf-8")

        def json(self) -> Any:
            return json.loads(self.text)

    class _DropMidCheckClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self) -> _DropMidCheckClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def get(self, path: str, params: dict[str, str] | None = None) -> _FlakyResp:
            del params
            if path.startswith("/app"):
                return _FlakyResp(200, text=rendered_html)
            if path == "/assets/index-TEST1234.js":
                return _FlakyResp(
                    200, content=(dist_dir / "assets" / "index-TEST1234.js").read_bytes()
                )
            if path == "/assets/index-TEST5678.css":
                return _FlakyResp(
                    200, content=(dist_dir / "assets" / "index-TEST5678.css").read_bytes()
                )
            if path == "/api/system/info":
                raise httpx.ConnectError("connection dropped mid-check")
            if path == "/api/v1/bots":
                raise httpx.ReadTimeout("timed out mid-check")
            return _FlakyResp(404)

    monkeypatch.setattr(httpx, "Client", _DropMidCheckClient)
    mid_report = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_mid",
        target_url="http://127.0.0.1:9999",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert mid_report.overall_passed is False
    assert mid_report.exit_code == 2
    assert any("/api/system/info unreachable" in err for err in mid_report.boot_errors)
    assert any("/api/v1/bots unreachable" in err for err in mid_report.boot_errors)
    assert mid_report.functional_errors == []


@pytest.mark.n1
def test_run_baseline_linux_real_rejects_pending_n3_while_local_deterministic_passes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx
    import src.qa.baseline as baseline_mod
    from src.n3_probe import N3ProbeReport

    fake_repo = tmp_path / "repo_n3"
    dist_dir = _init_git_repo_with_dist(fake_repo)
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )

    class _FakeResp:
        def __init__(self, status_code: int, text: str = "", content: bytes = b"") -> None:
            self.status_code = status_code
            self.text = text
            self.content = content or text.encode("utf-8")

        def json(self) -> Any:
            return json.loads(self.text)

    class _HealthyClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self) -> _HealthyClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def get(self, path: str, params: dict[str, str] | None = None) -> _FakeResp:
            del params
            if path.startswith("/app"):
                return _FakeResp(200, text=rendered_html)
            if path == "/assets/index-TEST1234.js":
                return _FakeResp(
                    200, content=(dist_dir / "assets" / "index-TEST1234.js").read_bytes()
                )
            if path == "/assets/index-TEST5678.css":
                return _FakeResp(
                    200, content=(dist_dir / "assets" / "index-TEST5678.css").read_bytes()
                )
            if path == "/api/system/info":
                return _FakeResp(
                    200,
                    text=json.dumps({"backend_mode": "emulated", "runtime_mode": "live_runtime"}),
                )
            if path == "/api/v1/bots":
                return _FakeResp(200, text=json.dumps({"bots": []}))
            return _FakeResp(404)

    monkeypatch.setattr(httpx, "Client", _HealthyClient)

    for pending_status in ("PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM"):
        monkeypatch.setattr(
            baseline_mod,
            "run_n3_probe",
            lambda st=pending_status: N3ProbeReport(
                timestamp_utc="2026-11-27T00:00:00Z",
                host_os="Linux",
                host_release="6.1.0",
                arch="x86_64",
                overall_status=st,
                linux_os_ready=True,
                network_isolation_ready=(st == "PENDING_LOCAL_LLM"),
                desktop_ready=False,
                local_llm_ready=False,
                checks=[],
                evidence_notes=[f"blocked:{st}"],
            ),
        )
        linux_rep = run_baseline(
            repo_root=fake_repo,
            output_dir=tmp_path / f"out_linux_{pending_status}",
            target_url="http://127.0.0.1:9999",
            lane="linux_real",
            build_frontend=False,
            skip_browser=True,
            use_isolated_lab=False,
            log_dir=tmp_path / "missing_logs",
        )
        assert linux_rep.n3_status == pending_status
        assert linux_rep.overall_passed is False
        assert linux_rep.exit_code != 0
        assert any("linux_real" in err for err in linux_rep.functional_errors)
        assert f"n3_probe:{pending_status}" in linux_rep.skipped_checks

    local_rep = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_local_det",
        target_url="http://127.0.0.1:9999",
        lane="local_deterministic",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert local_rep.overall_passed is True
    assert local_rep.exit_code == 0


@pytest.mark.n1
def test_run_baseline_agy_real_rejects_missing_or_mismatched_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil

    import httpx

    fake_repo = tmp_path / "repo_agy"
    dist_dir = _init_git_repo_with_dist(fake_repo)
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )

    state: dict[str, Any] = {
        "backend_mode": "emulated",
        "runtime_mode": "live_runtime",
        "agy_available": False,
    }

    class _FakeResp:
        def __init__(self, status_code: int, text: str = "", content: bytes = b"") -> None:
            self.status_code = status_code
            self.text = text
            self.content = content or text.encode("utf-8")

        def json(self) -> Any:
            return json.loads(self.text)

    class _AgyClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self) -> _AgyClient:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def get(self, path: str, params: dict[str, str] | None = None) -> _FakeResp:
            del params
            if path.startswith("/app"):
                return _FakeResp(200, text=rendered_html)
            if path == "/assets/index-TEST1234.js":
                return _FakeResp(
                    200, content=(dist_dir / "assets" / "index-TEST1234.js").read_bytes()
                )
            if path == "/assets/index-TEST5678.css":
                return _FakeResp(
                    200, content=(dist_dir / "assets" / "index-TEST5678.css").read_bytes()
                )
            if path == "/api/system/info":
                return _FakeResp(
                    200,
                    text=json.dumps(
                        {
                            "backend_mode": state["backend_mode"],
                            "runtime_mode": state["runtime_mode"],
                        }
                    ),
                )
            if path == "/api/v1/bots":
                return _FakeResp(200, text=json.dumps({"bots": []}))
            if path == "/api/agy/models":
                return _FakeResp(
                    200,
                    text=json.dumps({"available": state["agy_available"], "models": []}),
                )
            return _FakeResp(404)

    monkeypatch.setattr(httpx, "Client", _AgyClient)

    # 1) Missing agy binary + emulated server -> fails.
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "agy" else "/usr/bin/true")
    missing_rep = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_agy_missing",
        target_url="http://127.0.0.1:9999",
        lane="agy_real",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert missing_rep.overall_passed is False
    assert missing_rep.exit_code != 0
    assert any("agy" in err for err in missing_rep.functional_errors)

    # 2) agy in PATH, but server backend_mode is emulated -> still rejected!
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/agy")
    state["agy_available"] = True
    state["backend_mode"] = "emulated"
    emulated_rep = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_agy_emulated",
        target_url="http://127.0.0.1:9999",
        lane="agy_real",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert emulated_rep.overall_passed is False
    assert emulated_rep.exit_code != 0
    assert any("engine mismatch" in err for err in emulated_rep.functional_errors)

    # 3) agy in PATH + non-emulated backend + /api/agy/models available=True -> passes!
    state["backend_mode"] = "agy_real"
    ok_rep = run_baseline(
        repo_root=fake_repo,
        output_dir=tmp_path / "out_agy_ok",
        target_url="http://127.0.0.1:9999",
        lane="agy_real",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=tmp_path / "missing_logs",
    )
    assert ok_rep.overall_passed is True
    assert ok_rep.exit_code == 0
    assert "agy_cli" in ok_rep.real_services
