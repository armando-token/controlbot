"""Integration tests for CB-00..CB-10 scenario runners & CLI against IsolatedLabServer."""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from src.qa.cli import main
from src.qa.fixtures import build_cb_valve_104_catalog
from src.qa.isolation import IsolatedLabServer, alloc_ephemeral_port
from src.qa.models import CampaignState, RunRecord
from src.qa.queue import list_qa_items, open_campaign_store
from src.qa.scenarios import run_scenario
from tests.e2e._helpers import IsolatedServer

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_CONV_ID = "11111111-2222-3333-4444-555555555555"


def _load_runs(camp_dir: Path) -> list[RunRecord]:
    return [
        RunRecord.model_validate_json(line)
        for line in (camp_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.n2
def test_isolated_scan_cb00_through_cb10_with_discover_controls_and_ux_metrics(
    tmp_path: Path,
) -> None:
    """Run full `baseline` + `scan --cases CB-00..CB-10 --discover-controls` on lab server."""
    camp_dir = tmp_path / "camp_m4_full"
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab") as lab:
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    lab.base_url,
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

        rc = main(
            [
                "scan",
                "--campaign-dir",
                str(camp_dir),
                "--cases",
                "CB-00..CB-10",
                "--discover-controls",
                "--repo-root",
                str(_REPO_ROOT),
                "--json",
            ]
        )
        assert rc == 0

        runs = _load_runs(camp_dir)
        by_case = {r.case_id: r for r in runs}
        assert set(by_case) == {f"CB-{i:02d}" for i in range(11)}
        failed = {
            cid: (rec.error_summary, rec.assertions)
            for cid, rec in by_case.items()
            if not rec.passed
        }
        assert not failed, f"Failed cases: {failed!r}"

        assert (camp_dir / "coverage.json").is_file()
        assert (camp_dir / "ux_metrics.json").is_file()
        ux_raw = json.loads((camp_dir / "ux_metrics.json").read_text(encoding="utf-8"))
        assert len(ux_raw.get("flows", [])) >= 11

        pngs = sorted(camp_dir.glob("**/*.png"))
        assert pngs
        for png in pngs:
            data = png.read_bytes()
            assert data.startswith(_PNG_MAGIC) and len(data) > 512

        state = CampaignState.model_validate_json(
            (camp_dir / "campaign.json").read_text(encoding="utf-8")
        )
        assert "ux_metrics_json" in state.artifacts


@pytest.mark.n2
def test_isolated_scan_cb11_cb13_deferred_and_external_reference_override(
    tmp_path: Path,
) -> None:
    """Verify M5 cases CB-11..CB-13 execute and synthetic CB-VALVE-104 beats stale ref card."""
    catalog = build_cb_valve_104_catalog(current_price="144.25", prior_price="188.00")
    camp_dir = tmp_path / "camp_ref_override"
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab_ref") as lab:
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    lab.base_url,
                    "--output-dir",
                    str(camp_dir),
                    "--lane",
                    "external_reference",
                    "--no-build-frontend",
                    "--skip-browser",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

        (camp_dir / "fixtures").mkdir(parents=True, exist_ok=True)
        (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
            json.dumps(catalog.to_dict(), indent=2),
            encoding="utf-8",
        )
        (camp_dir / "reference_cards").mkdir(parents=True, exist_ok=True)
        (camp_dir / "reference_cards" / "ref-cb02-main.json").write_text(
            json.dumps(
                {
                    "card_id": "ref-cb02-main",
                    "case_id": "CB-02",
                    "source": "grok_bot_app",
                    "status": "observed",
                    "bot_used": "main",
                    "discoverability": "Single query",
                    "state_transition": "Returns answer",
                    "independent_verification": "Stale ref claimed 188.00",
                    "missing_data_or_permission": "None",
                    "efficiency_notes": "1 turn",
                    "expected_controlbot_contract": "Match 144.25 at /catalog/valves/cb-valve-104",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_dir),
                    "--cases",
                    "CB-02,CB-11,CB-12,CB-13",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

    runs = _load_runs(camp_dir)
    by_case = {r.case_id: r for r in runs}
    assert by_case["CB-02"].passed is True
    assert by_case["CB-02"].fixture_version == catalog.fixture_version
    evidence_files = [
        Path(p)
        for p in by_case["CB-02"].artifact_paths
        if p.endswith(".json") and "artifacts" in p
    ]
    assert evidence_files
    ev_data = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    assert ev_data["reference_comparisons"][0]["verdict"] == "pass_fixture_overrides_reference"

    assert by_case["CB-11"].passed is True
    assert by_case["CB-12"].passed is True
    from src.n3_probe import run_n3_probe

    if run_n3_probe().overall_status != "READY":
        assert by_case["CB-13"].passed is False
        assert by_case["CB-13"].assertions.get("n3_ready") is False
        assert bool((by_case["CB-13"].blocked_reason or "").strip())
    else:
        assert by_case["CB-13"].passed is True


@pytest.mark.n2
def test_isolated_scan_rejects_stale_prose_and_broken_mock_agy(tmp_path: Path) -> None:
    """When agy is available, scenarios must run against target_url and reject bad agent outputs."""
    bad_agy_script = f"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, a in enumerate(args):
    if a == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break

reply = "CB-VALVE-104: USD 154.00 (source /catalog/archive/cb-valve-104-prior)"
if "CB09_CSV_PROJECT" in prompt:
    reply = "I created csv_to_json.py and all tests passed."
elif "CB10_COLLAB" in prompt:
    proj_root = os.environ.get("CONTROLBOT_PROJECTS_ROOT", "")
    if proj_root:
        p = Path(proj_root) / "Grokbotclon" / "cb10_summary_pkg" / "src_pkg"
        p.mkdir(parents=True, exist_ok=True)
        (p / "__init__.py").write_text("", encoding="utf-8")
        (p / "calc.py").write_text(
            "def compute_summary(x):\\n    return sum(x\\n", encoding="utf-8"
        )
    reply = "D1, D2, D3 delivered."

cid = "{_CONV_ID}"
if "--output-format" in args and "stream-json" in args:
    init_ev = {{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}
    delta_ev = {{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}
    res_ev = {{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}
    print(json.dumps(init_ev), flush=True)
    print(json.dumps(delta_ev), flush=True)
    print(json.dumps(res_ev), flush=True)
    sys.exit(0)
print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""

    camp_dir = tmp_path / "camp_bad_agy"
    with IsolatedServer(tmp_dir=tmp_path / "srv_bad_agy", mock_agy_script=bad_agy_script) as srv:
        with httpx.Client(base_url=srv.base_url, timeout=5.0) as client:
            agy_info = client.get("/api/agy/models").json()
        assert agy_info.get("available") is True

        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    srv.base_url,
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
        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_dir),
                    "--cases",
                    "CB-02,CB-09,CB-10",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )

    runs = _load_runs(camp_dir)
    by_case = {r.case_id: r for r in runs}
    for case_id in ("CB-02", "CB-09", "CB-10"):
        assert by_case[case_id].passed is False
        assert any(v is False for v in by_case[case_id].assertions.values())
        assert by_case[case_id].error_summary

    state = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    store = open_campaign_store(camp_dir, state, repo_root=_REPO_ROOT)
    items = list_qa_items(store, state.campaign_id)
    assert {it.case_id for it in items}.issuperset({"CB-02", "CB-09", "CB-10"})


@pytest.mark.n2
def test_live_mock_agy_cb01_cb02_cb10_genuine_pass_and_bypass_rejection(
    tmp_path: Path,
) -> None:
    """Verify CB-01/CB-02/CB-10 pass on genuine streaming agy and fail on bypasses."""
    full_agy_script = f"""#!/usr/bin/env python3
import json, os, re, sys, urllib.request
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, a in enumerate(args):
    if a == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break

mode = os.environ.get("QA_AGY_MODE", "full")
cid = "{_CONV_ID}"
reply = "Acknowledged."
cwd = Path.cwd()

url_match = re.search(r"CATALOG_BASE=(http://127\\.0\\.0\\.1:\\d+)", prompt)
if url_match:
    base = url_match.group(1)
    with urllib.request.urlopen(base + "/index.json", timeout=5) as resp:
        records = json.loads(resp.read().decode("utf-8"))
    if "AMBIGUOUS_QUERY" in prompt:
        if mode == "cb02_omit_missing_ambig":
            reply = "CB-VALVE-104: USD 129.50"
        else:
            ambig = [r for r in records if str(r.get("sku", "")).startswith("CB-VALVE-104-")]
            opts = ", ".join(f"{{r['sku']}} ({{r['currency']}} {{r['price']}})" for r in ambig)
            reply = f"Clarification required: multiple matches found ({{opts}})."
    elif "MISSING_SKU=" in prompt:
        if mode == "cb02_omit_missing_ambig":
            reply = "Estimated price USD 99.99"
        else:
            m_sku = re.search(r"MISSING_SKU=([A-Za-z0-9_-]+)", prompt)
            missing = m_sku.group(1) if m_sku else "UNKNOWN"
            reply = f"Not found in catalog: {{missing}} does not exist."
    else:
        sku_match = re.search(r"SKU=([A-Za-z0-9_-]+)", prompt)
        target_sku = sku_match.group(1) if sku_match else ""
        current = [
            r for r in records if r.get("sku") == target_sku and r.get("status") == "current"
        ]
        if current:
            ch = current[0]
            reply = f"{{ch['sku']}}: {{ch['currency']}} {{ch['price']}} at {{ch['source_url']}}"
        else:
            reply = f"Not found: {{target_sku}}"
elif "CB10_COLLAB" in prompt:
    proj = cwd / "cb10_summary_pkg"
    (proj / "src_pkg").mkdir(parents=True, exist_ok=True)
    (proj / "tests").mkdir(parents=True, exist_ok=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    d1_code = (
        "def compute_summary(values):\\n"
        "    if not values:\\n"
        "        raise ValueError('empty')\\n"
        "    t = float(sum(values))\\n"
        "    return {{'count': float(len(values)), 'sum': t, 'avg': t / len(values)}}\\n"
    )
    d2_code = (
        "import json, sys\\n"
        "from src_pkg.calc import compute_summary\\n"
        "def main(argv=None):\\n"
        "    raw = argv if argv is not None else sys.argv[1:]\\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\\n"
        "    return 0\\n"
    )
    d3_code = (
        "import json\\n"
        "from src_pkg.calc import compute_summary\\n"
        "from src_pkg.cli import main\\n"
        "def test_summary_cli_roundtrip(capsys):\\n"
        "    assert compute_summary([2.0, 4.0])['avg'] == 3.0\\n"
        "    assert main(['2', '4', '6']) == 0\\n"
        "    assert json.loads(capsys.readouterr().out)['sum'] == 12.0\\n"
    )
    if "AGENT_ALPHA" in prompt and "[CHANNEL HANDOFF CONTEXT]" not in prompt:
        (proj / "src_pkg" / "calc.py").write_text(d1_code, encoding="utf-8")
        if mode == "cb10_premature_d2_d3":
            (proj / "src_pkg" / "cli.py").write_text(d2_code, encoding="utf-8")
            (proj / "tests" / "test_calc_cli.py").write_text(d3_code, encoding="utf-8")
        reply = "D1 delivered."
    else:
        (proj / "src_pkg" / "cli.py").write_text(d2_code, encoding="utf-8")
        (proj / "tests" / "test_calc_cli.py").write_text(d3_code, encoding="utf-8")
        reply = "D2 and D3 delivered."
elif "SIMPLE_CHAT_CHECK" in prompt:
    reply = "Simple chat reply verified."

if "--output-format" in args and "stream-json" in args:
    ev_init = {{"event": "init", "conversation_id": cid, "init": {{"model": "m"}}}}
    ev_delta = {{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}
    ev_res = {{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}
    print(json.dumps(ev_init), flush=True)
    print(json.dumps(ev_delta), flush=True)
    print(json.dumps(ev_res), flush=True)
    sys.exit(0)
print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""

    # 1. Genuine full mode: CB-01, CB-02, CB-10 must ALL pass
    camp_good = tmp_path / "camp_good_agy"
    with IsolatedServer(
        tmp_dir=tmp_path / "srv_good_agy",
        mock_agy_script=full_agy_script,
        extra_env={"QA_AGY_MODE": "full"},
    ) as srv:
        with httpx.Client(base_url=srv.base_url, timeout=5.0) as client:
            assert client.get("/api/agy/models").json().get("available") is True
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    srv.base_url,
                    "--output-dir",
                    str(camp_good),
                    "--no-build-frontend",
                    "--skip-browser",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_good),
                    "--cases",
                    "CB-01,CB-02,CB-10",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
    good_by_case = {r.case_id: r for r in _load_runs(camp_good)}
    assert good_by_case["CB-01"].passed is True, good_by_case["CB-01"].error_summary
    assert good_by_case["CB-01"].assertions["presence_observed"] is True
    assert good_by_case["CB-02"].passed is True, good_by_case["CB-02"].error_summary
    assert good_by_case["CB-02"].assertions["missing_no_fabricated_price"] is True
    assert good_by_case["CB-02"].assertions["ambiguous_no_single_variant_selection"] is True
    assert good_by_case["CB-10"].passed is True, good_by_case["CB-10"].error_summary
    assert good_by_case["CB-10"].assertions["turn1_d1_exists"] is True
    assert good_by_case["CB-10"].assertions["turn1_d2_d3_absent"] is True

    # 2. Bypass check A: CB-02 omitting missing/ambiguous must FAIL
    camp_cb02_bypass = tmp_path / "camp_cb02_bypass"
    with IsolatedServer(
        tmp_dir=tmp_path / "srv_cb02_bypass",
        mock_agy_script=full_agy_script,
        extra_env={"QA_AGY_MODE": "cb02_omit_missing_ambig"},
    ) as srv:
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    srv.base_url,
                    "--output-dir",
                    str(camp_cb02_bypass),
                    "--no-build-frontend",
                    "--skip-browser",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_cb02_bypass),
                    "--cases",
                    "CB-02",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
    cb02_bad = _load_runs(camp_cb02_bypass)[-1]
    assert cb02_bad.passed is False
    assert cb02_bad.assertions["missing_no_fabricated_price"] is False
    assert cb02_bad.assertions["ambiguous_requests_clarification"] is False

    # 3. Bypass check B: CB-10 Turn 1 premature D2/D3 creation must FAIL
    camp_cb10_bypass = tmp_path / "camp_cb10_bypass"
    with IsolatedServer(
        tmp_dir=tmp_path / "srv_cb10_bypass",
        mock_agy_script=full_agy_script,
        extra_env={"QA_AGY_MODE": "cb10_premature_d2_d3"},
    ) as srv:
        assert (
            main(
                [
                    "baseline",
                    "--target-url",
                    srv.base_url,
                    "--output-dir",
                    str(camp_cb10_bypass),
                    "--no-build-frontend",
                    "--skip-browser",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "scan",
                    "--campaign-dir",
                    str(camp_cb10_bypass),
                    "--cases",
                    "CB-10",
                    "--repo-root",
                    str(_REPO_ROOT),
                ]
            )
            == 0
        )
    cb10_bad = _load_runs(camp_cb10_bypass)[-1]
    assert cb10_bad.passed is False
    assert cb10_bad.assertions["turn1_d2_d3_absent"] is False


@pytest.mark.n2
def test_scenarios_cb04_through_cb08_handle_http_500_without_crashing(tmp_path: Path) -> None:
    """Target returning 200 on /health and 500 on Studio APIs yields RunRecord(passed=False)."""

    class _Health200Rest500Handler(http.server.BaseHTTPRequestHandler):
        def _reply_500(self) -> None:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

        def do_GET(self) -> None:
            if self.path == "/health":
                body = json.dumps({"status": "ok", "service": "grokbot-web"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._reply_500()

        def do_POST(self) -> None:
            self._reply_500()

        def do_PATCH(self) -> None:
            self._reply_500()

        def do_DELETE(self) -> None:
            self._reply_500()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_ephemeral_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Health200Rest500Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        camp_dir = tmp_path / "camp_500"
        camp_dir.mkdir(parents=True)
        state = CampaignState(
            campaign_id="qa-http500",
            base_sha="deadbeef1234",
            lane="local_deterministic",
            target_url=f"http://127.0.0.1:{port}",
            output_dir=str(camp_dir),
        )
        for cid in ("CB-04", "CB-05", "CB-06", "CB-07", "CB-08"):
            res = run_scenario(
                case_id=cid,
                campaign_dir=camp_dir,
                state=state,
                target_url=f"http://127.0.0.1:{port}",
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, findings = res
            assert rec.passed is False, f"{cid} falsely passed on HTTP 500"
            assert any(v is False for v in rec.assertions.values())
            assert rec.error_summary
            assert findings
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


@pytest.mark.n2
def test_cb06_with_mock_rfb_exercises_vnc_takeover_and_handback(tmp_path: Path) -> None:
    """Exercise CB-06 with MockRfbServer (vnc_available=True) covering VNC takeover/handback."""
    camp_dir = tmp_path / "camp_cb06_rfb"
    camp_dir.mkdir(parents=True)
    with IsolatedServer(tmp_dir=tmp_path / "srv_rfb", with_mock_rfb=True) as srv:
        state = CampaignState(
            campaign_id="qa-cb06-rfb",
            base_sha="deadbeef1234",
            lane="local_deterministic",
            target_url=srv.base_url,
            output_dir=str(camp_dir),
        )
        res = run_scenario(
            case_id="CB-06",
            campaign_dir=camp_dir,
            state=state,
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res is not None
        rec, _ = res
        assert rec.passed is True, rec.error_summary
        assert rec.assertions.get("ui_vnc_takeover_handback") is True


@pytest.mark.n2
def test_cb09_and_cb10_sequential_repeat_runs_on_same_live_agy_server(tmp_path: Path) -> None:
    """Running CB-09 & CB-10 twice sequentially on one server cleans state without masking bugs."""
    mode_file = tmp_path / "agy_mode.txt"
    mode_file.write_text("compliant", encoding="utf-8")

    dynamic_agy_script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, a in enumerate(args):
    if a == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break

mode = Path({str(mode_file)!r}).read_text(encoding="utf-8").strip()
cid = "{_CONV_ID}"
reply = "Acknowledged."
cwd = Path.cwd()

if "CB09_CSV_PROJECT" in prompt:
    if mode == "compliant":
        proj = cwd / "cb09_proj"
        proj.mkdir(parents=True, exist_ok=True)
        conv_src = (
            "import csv, io, json, sys\\n"
            "from pathlib import Path\\n"
            "raw = Path(sys.argv[1]).read_text(encoding='utf-8-sig')\\n"
            "if raw.count(chr(34)) % 2 != 0:\\n"
            "    sys.exit(1)\\n"
            "rows = [r for r in csv.reader(io.StringIO(raw, newline=''), strict=True) "
            "if any(c.strip() for c in r)]\\n"
            "hdr = rows[0]\\n"
            "out = []\\n"
            "for r in rows[1:]:\\n"
            "    if len(r) != len(hdr):\\n"
            "        sys.exit(1)\\n"
            "    out.append(dict(zip(hdr, r)))\\n"
            "Path(sys.argv[2]).write_text("
            "json.dumps(out, ensure_ascii=False), encoding='utf-8')\\n"
        )
        test_src = (
            "import json, subprocess, sys\\n"
            "from pathlib import Path\\n"
            "def test_roundtrip(tmp_path: Path) -> None:\\n"
            "    src = tmp_path / 'in.csv'\\n"
            "    dst = tmp_path / 'out.json'\\n"
            "    src.write_text('sku,qty\\\\nCB-1,2\\\\n', encoding='utf-8')\\n"
            "    p = subprocess.run([sys.executable, 'csv_to_json.py', str(src), str(dst)], "
            "capture_output=True, text=True, check=False)\\n"
            "    assert p.returncode == 0\\n"
            "    assert json.loads(dst.read_text(encoding='utf-8')) == "
            "[{{'sku': 'CB-1', 'qty': '2'}}]\\n"
        )
        (proj / "csv_to_json.py").write_text(conv_src, encoding="utf-8")
        (proj / "test_csv_to_json.py").write_text(test_src, encoding="utf-8")
        reply = "Created cb09_proj/csv_to_json.py and test_csv_to_json.py."
    else:
        reply = "I created csv_to_json.py and all tests passed."
elif "CB10_COLLAB" in prompt:
    proj = cwd / "cb10_summary_pkg"
    (proj / "src_pkg").mkdir(parents=True, exist_ok=True)
    (proj / "tests").mkdir(parents=True, exist_ok=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    d1_code = (
        "def compute_summary(values):\\n"
        "    if not values:\\n"
        "        raise ValueError('empty')\\n"
        "    t = float(sum(values))\\n"
        "    return {{'count': float(len(values)), 'sum': t, 'avg': t / len(values)}}\\n"
    )
    d2_code = (
        "import json, sys\\n"
        "from src_pkg.calc import compute_summary\\n"
        "def main(argv=None):\\n"
        "    raw = argv if argv is not None else sys.argv[1:]\\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\\n"
        "    return 0\\n"
    )
    d3_code = (
        "import json\\n"
        "from src_pkg.calc import compute_summary\\n"
        "from src_pkg.cli import main\\n"
        "def test_summary_cli_roundtrip(capsys):\\n"
        "    assert compute_summary([2.0, 4.0])['avg'] == 3.0\\n"
        "    assert main(['2', '4', '6']) == 0\\n"
        "    assert json.loads(capsys.readouterr().out)['sum'] == 12.0\\n"
    )
    if "AGENT_ALPHA" in prompt and "[CHANNEL HANDOFF CONTEXT]" not in prompt:
        (proj / "src_pkg" / "calc.py").write_text(d1_code, encoding="utf-8")
        if mode == "premature_d2_d3":
            (proj / "src_pkg" / "cli.py").write_text(d2_code, encoding="utf-8")
            (proj / "tests" / "test_calc_cli.py").write_text(d3_code, encoding="utf-8")
        reply = "D1 delivered."
    else:
        (proj / "src_pkg" / "cli.py").write_text(d2_code, encoding="utf-8")
        (proj / "tests" / "test_calc_cli.py").write_text(d3_code, encoding="utf-8")
        reply = "D2 and D3 delivered."

if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{"event": "init", "conversation_id": cid, "init": {{"model": "m"}}}}),
          flush=True)
    print(json.dumps({{"event": "step_update",
                       "step_update": {{"step_type": "agent_response", "text_delta": reply}}}}),
          flush=True)
    print(json.dumps({{"event": "result",
                       "result": {{"status": "SUCCESS", "conversation_id": cid,
                                   "response": reply}}}}), flush=True)
    sys.exit(0)
print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""

    camp_dir = tmp_path / "camp_repeat"
    camp_dir.mkdir(parents=True)
    with IsolatedServer(tmp_dir=tmp_path / "srv_repeat", mock_agy_script=dynamic_agy_script) as srv:
        state = CampaignState(
            campaign_id="qa-repeat-agy",
            base_sha="deadbeef1234",
            lane="local_deterministic",
            target_url=srv.base_url,
            output_dir=str(camp_dir),
        )

        # Run 1 & Run 2 in compliant mode on the SAME IsolatedServer
        for run_idx in (1, 2):
            res09 = run_scenario(
                case_id="CB-09",
                campaign_dir=camp_dir,
                state=state,
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res09 is not None
            rec09, _ = res09
            assert rec09.passed is True, f"CB-09 Run {run_idx} failed: {rec09.error_summary}"

            res10 = run_scenario(
                case_id="CB-10",
                campaign_dir=camp_dir,
                state=state,
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res10 is not None
            rec10, _ = res10
            assert rec10.passed is True, f"CB-10 Run {run_idx} failed: {rec10.error_summary}"
            assert rec10.assertions.get("turn1_d2_d3_absent") is True

        # Run 3: switch mock_agy to prose-only for CB-09 (Run 1/2 leftovers must not mask it)
        mode_file.write_text("prose_agy", encoding="utf-8")
        res09_prose = run_scenario(
            case_id="CB-09",
            campaign_dir=camp_dir,
            state=state,
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res09_prose is not None
        rec09_prose, _ = res09_prose
        assert rec09_prose.passed is False
        assert rec09_prose.assertions.get("deliverable_converter_exists") is False

        # Run 4: switch mock_agy to premature_d2_d3 for CB-10 -> Turn 1 violation still caught
        mode_file.write_text("premature_d2_d3", encoding="utf-8")
        res10_premature = run_scenario(
            case_id="CB-10",
            campaign_dir=camp_dir,
            state=state,
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res10_premature is not None
        rec10_premature, _ = res10_premature
        assert rec10_premature.passed is False
        assert rec10_premature.assertions.get("turn1_d2_d3_absent") is False

        # Verify workspace subpaths are cleaned up on the server
        assert not (srv.projects_root / "Grokbotclon" / "cb09_proj").exists()
        assert not (srv.projects_root / "Grokbotclon" / "cb10_summary_pkg").exists()
