"""Integration Tier-5 regression tests against IsolatedServer, LabStack & Playwright."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from src.doctor import CheckResult, CheckStatus, EvidenceLevel
from src.n3_probe import N3ProbeReport
from src.qa.isolation import IsolatedLabServer, StrictPlaywrightSession
from src.qa.models import CampaignState
from src.qa.scenarios import run_scenario
from src.qa.scenarios._common import _EphemeralLabStack, run_coro_sync
from tests.e2e._helpers import IsolatedServer

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONV_ID = "11111111-2222-3333-4444-555555555555"


def _make_state(camp_dir: Path, target_url: str) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-t5-int",
        base_sha="deadbeef1234",
        lane="local_deterministic",
        target_url=target_url,
        output_dir=str(camp_dir),
    )
    (camp_dir / "campaign.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return state


@pytest.mark.n2
def test_t5_int_cb01_markdown_agy_reply_and_non_agy_ui_pass_playwright(tmp_path: Path) -> None:
    """CB-01 passes Playwright when mock agy returns Markdown AND in non-agy UI mode."""
    md_agy_script = f"""#!/usr/bin/env python3
import json, sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = "**CB-01 Status**: Verified `OK` — response persisted cleanly."
cid = "{_CONV_ID}"
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
    camp_md = tmp_path / "camp_cb01_md"
    with IsolatedServer(tmp_dir=tmp_path / "srv_cb01_md", mock_agy_script=md_agy_script) as srv:
        res_md = run_scenario(
            case_id="CB-01",
            campaign_dir=camp_md,
            state=_make_state(camp_md, srv.base_url),
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_md is not None
        rec_md, _ = res_md
        assert rec_md.passed is True, rec_md.error_summary
        assert rec_md.assertions["ui_assistant_reply_visible"] is True
        assert rec_md.assertions["ui_thread_switch_and_reload_persisted"] is True

    # Non-agy mode against IsolatedLabServer must visibly render error + ApprovalCard
    camp_noagy = tmp_path / "camp_cb01_noagy"
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab_cb01") as lab:
        res_noagy = run_scenario(
            case_id="CB-01",
            campaign_dir=camp_noagy,
            state=_make_state(camp_noagy, lab.base_url),
            target_url=lab.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_noagy is not None
        rec_noagy, _ = res_noagy
        assert rec_noagy.passed is True, rec_noagy.error_summary
        assert rec_noagy.assertions["ui_assistant_error_visible"] is True
        assert rec_noagy.assertions["ui_approval_card_visible"] is True


@pytest.mark.n2
def test_t5_int_cb07_ephemeral_lab_stack_failed_task_and_real_409_actionability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CB-07 with failing /api/tasks does not raise IndexError and evaluates real 409 text."""
    camp_dir = tmp_path / "camp_cb07_int"
    with (
        _EphemeralLabStack(fixture_mode="default") as lab,
        IsolatedLabServer(
            repo_root=_REPO_ROOT,
            base_dir=tmp_path / "lab_cb07",
            extra_env=lab.env_vars(),
        ) as srv,
    ):
        async def _failed_poll(*_a: Any, **_kw: Any) -> dict[str, Any]:
            return {"run": {"status": "failed"}}

        monkeypatch.setattr("src.qa.scenarios.cb_07._poll_task_terminal", _failed_poll)
        res = run_scenario(
            case_id="CB-07",
            campaign_dir=camp_dir,
            state=_make_state(camp_dir, srv.base_url),
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res is not None
        rec, _ = res
        assert rec.passed is False
        assert rec.assertions["effect_sim_task_succeeded"] is False
        assert rec.assertions["effect_sim_single_apply"] is False
        assert rec.assertions["ui_approval_card_deny"] is True
        assert rec.assertions["ui_deny_zero_effects"] is True
        assert rec.assertions.get("scenario_execution_completed", True) is True
        ux = json.loads((camp_dir / "ux_metrics.json").read_text(encoding="utf-8"))
        assert ux["flows"][-1]["error_actionable"] is False


@pytest.mark.n2
def test_t5_int_cb13_ready_rejects_emulated_isolated_server_and_cb09_restores_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CB-13 READY fails on emulated IsolatedServer; CB-09 restores bot_chief.project_name=None."""
    rep_ready = N3ProbeReport(
        timestamp_utc="2026-11-27T00:00:00Z",
        host_os="Linux",
        host_release="6.1.0",
        arch="x86_64",
        overall_status="READY",
        linux_os_ready=True,
        network_isolation_ready=True,
        desktop_ready=True,
        local_llm_ready=True,
        checks=[
            CheckResult(
                name="network_isolation_a11",
                status=CheckStatus.PASS,
                required_for=EvidenceLevel.N3,
                summary="Mocked PASS",
            )
        ],
        evidence_notes=["Mocked READY"],
    )
    monkeypatch.setattr("src.qa.scenarios.cb_13._run_verify_n3_script", lambda _r: (0, "ok", ""))
    monkeypatch.setattr(
        "src.qa.scenarios.cb_13._run_pytest_n3", lambda _r, *, strict=False: (0, "2 passed", "")
    )

    camp_13 = tmp_path / "camp_cb13_int"
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab_cb13") as lab:
        res_13 = run_scenario(
            case_id="CB-13",
            campaign_dir=camp_13,
            state=_make_state(camp_13, lab.base_url),
            target_url=lab.base_url,
            repo_root=_REPO_ROOT,
            n3_report=rep_ready,
        )
        assert res_13 is not None
        rec_13, _ = res_13
        assert rec_13.passed is False
        assert rec_13.emulated is True
        assert rec_13.assertions["local_llm_backend_active"] is False

    # CB-09 real IsolatedServer with bot_chief.project_name=None -> restored to None
    cb09_agy = f"""#!/usr/bin/env python3
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
cid = "{_CONV_ID}"
reply = "Acknowledged."
if "CB09_CSV_PROJECT" in prompt:
    proj = Path.cwd() / "cb09_proj"
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
        "Path(sys.argv[2]).write_text(json.dumps(out, ensure_ascii=False), encoding='utf-8')\\n"
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
        "    assert json.loads(dst.read_text(encoding='utf-8')) "
        "== [{{'sku': 'CB-1', 'qty': '2'}}]\\n"
    )
    (proj / "csv_to_json.py").write_text(conv_src, encoding="utf-8")
    (proj / "test_csv_to_json.py").write_text(test_src, encoding="utf-8")
    reply = "Created cb09_proj/csv_to_json.py and test_csv_to_json.py."
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
    camp_09 = tmp_path / "camp_cb09_int"
    with IsolatedServer(
        tmp_dir=tmp_path / "srv_cb09_int",
        mock_agy_script=cb09_agy,
    ) as srv:
        with httpx.Client(base_url=srv.base_url, timeout=5.0) as client:
            p_resp = client.patch("/api/v1/bots/bot_chief", json={"project_name": None})
            assert p_resp.status_code == 200
            assert p_resp.json()["project_name"] is None

        res_09 = run_scenario(
            case_id="CB-09",
            campaign_dir=camp_09,
            state=_make_state(camp_09, srv.base_url),
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_09 is not None
        rec_09, _ = res_09
        assert rec_09.passed is True, rec_09.error_summary

        with httpx.Client(base_url=srv.base_url, timeout=5.0) as client:
            bots = client.get("/api/v1/bots").json()["bots"]
            chief = next(b for b in bots if b["id"] == "bot_chief")
            assert chief["project_name"] is None


@pytest.mark.n2
def test_t5_w2_int_cb01_markdown_table_hr_tasklist_image_pass_playwright(
    tmp_path: Path,
) -> None:
    """CB-01 passes Playwright on Markdown starting with table, HR, task-list, or image."""
    variants = [
        ("table", "| Check | Status |\n| --- | --- |\n| CB-01 | OK |"),
        ("hr", "---\n**CB-01 Status**: Verified OK"),
        ("tasklist", "- [x] CB-01 Verified OK"),
        ("image", ""),
    ]
    png_1x1 = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    )
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_{label}.txt"
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_{label}"
        with IsolatedServer(tmp_dir=tmp_path / f"srv_cb01_{label}", mock_agy_script=script) as srv:
            att_id = ""
            if label == "image":
                with httpx.Client(base_url=srv.base_url, timeout=5.0) as client:
                    up_resp = client.post(
                        "/api/v1/attachments",
                        params={"filename": "badge.png"},
                        content=png_1x1,
                        headers={"Content-Type": "image/png"},
                    )
                    assert up_resp.status_code == 201, up_resp.text
                    att_id = str(up_resp.json()["id"])
                reply_file.write_text(
                    f"![badge](/api/v1/attachments/{att_id})\nCB-01 Image OK",
                    encoding="utf-8",
                )
            else:
                reply_file.write_text(reply_body, encoding="utf-8")

            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True

            if label == "image":
                async def _check_img_rendered(
                    base_url: str = srv.base_url,
                ) -> tuple[
                    bool,
                    int,
                    str,
                    list[str],
                    list[str],
                    list[tuple[int, str]],
                    list[str],
                ]:
                    async with StrictPlaywrightSession(headless=True) as pw:
                        await pw.page.goto(
                            f"{base_url}/app", wait_until="networkidle", timeout=15000
                        )
                        img = pw.page.locator(".gb-markdown img[alt='badge']").first
                        await img.wait_for(state="visible", timeout=10000)
                        src_attr = str(await img.get_attribute("src") or "")
                        loaded = await img.evaluate(
                            "el => ({ complete: Boolean(el.complete), "
                            "naturalWidth: Number(el.naturalWidth) })"
                        )
                        return (
                            bool(loaded["complete"]),
                            int(loaded["naturalWidth"]),
                            src_attr,
                            list(pw.console_errors),
                            list(pw.page_errors),
                            list(pw.http_errors),
                            list(pw.external_requests),
                        )

                complete, natural_w, src_attr, c_err, p_err, h_err, ext_req = run_coro_sync(
                    _check_img_rendered()
                )
                assert complete is True
                assert natural_w > 0
                assert f"/api/v1/attachments/{att_id}" in src_attr
                assert not c_err and not p_err and not h_err and not ext_req


@pytest.mark.n2
def test_t5_w2_int_cb07_real_lab_actionable_and_stale_effect_on_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real CB-07 lab run achieves error_actionable=True; pre-seeded failed task rejects replay."""
    # Part A: Unmodified real _EphemeralLabStack + IsolatedLabServer -> passed & actionable
    camp_real = tmp_path / "camp_cb07_real_w2"
    with (
        _EphemeralLabStack(fixture_mode="default") as lab,
        IsolatedLabServer(
            repo_root=_REPO_ROOT,
            base_dir=tmp_path / "lab_cb07_real_w2",
            extra_env=lab.env_vars(),
        ) as srv,
    ):
        res_real = run_scenario(
            case_id="CB-07",
            campaign_dir=camp_real,
            state=_make_state(camp_real, srv.base_url),
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_real is not None
        rec_real, _ = res_real
        assert rec_real.passed is True, rec_real.error_summary
        ux_real = json.loads((camp_real / "ux_metrics.json").read_text(encoding="utf-8"))
        assert ux_real["flows"][-1]["error_actionable"] is True

    # Part B: Pre-seeded effect_sim (base_applied=1) + failing task -> replay/conflict False
    camp_stale = tmp_path / "camp_cb07_stale_w2"
    with (
        _EphemeralLabStack(fixture_mode="default") as lab2,
        IsolatedLabServer(
            repo_root=_REPO_ROOT,
            base_dir=tmp_path / "lab_cb07_stale_w2",
            extra_env=lab2.env_vars(),
        ) as srv2,
    ):
        seed_resp = httpx.post(
            f"{lab2.effect_sim_url}/api/effects/apply",
            json={
                "idempotency_key": "pre-existing-key",
                "asset_id": "bomba-34-a1",
                "action": "ack_alarm",
                "params": {},
            },
            timeout=5.0,
        )
        assert seed_resp.status_code == 200

        async def _failed_poll(*_a: Any, **_kw: Any) -> dict[str, Any]:
            return {"run": {"status": "failed"}}

        monkeypatch.setattr("src.qa.scenarios.cb_07._poll_task_terminal", _failed_poll)
        res_stale = run_scenario(
            case_id="CB-07",
            campaign_dir=camp_stale,
            state=_make_state(camp_stale, srv2.base_url),
            target_url=srv2.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_stale is not None
        rec_stale, _ = res_stale
        assert rec_stale.passed is False
        assert rec_stale.assertions["effect_sim_task_succeeded"] is False
        assert rec_stale.assertions["effect_sim_single_apply"] is False
        assert rec_stale.assertions["effect_sim_replay_dedup"] is False
        assert rec_stale.assertions["effect_sim_conflict_409"] is False


@pytest.mark.n2
def test_t5_w3_int_cb01_five_markdown_constructs_pass_playwright(tmp_path: Path) -> None:
    """CB-01 passes Playwright on inline code, fenced bold, reflink def, escapes & autolink."""
    variants = [
        ("inline_code_asterisks", "Result: `*CB-01* *OK*`"),
        ("fenced_code_bold", "```markdown\n**CB-01** **OK**\n```"),
        ("ref_link_def", "[ref]: https://example.local\nCB-01 OK"),
        ("escaped_stars", r"\*CB-01\* \*OK\*"),
        ("autolink", "<https://example.local>\nCB-01 OK"),
    ]
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_w3_{label}.txt"
        reply_file.write_text(reply_body, encoding="utf-8")
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_w3_{label}"
        with IsolatedServer(
            tmp_dir=tmp_path / f"srv_cb01_w3_{label}",
            mock_agy_script=script,
        ) as srv:
            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True


@pytest.mark.n2
def test_t5_w3_int_cb03_rejects_broken_interrupt_false_and_passes_genuine_cancel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CB-03 passes on genuine cancel and fails when /interrupt returns interrupted=False."""
    cb03_agy_script = f"""#!/usr/bin/env python3
import json, re, sys, time
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

cid = "{_CONV_ID}"
if "CANCEL_SLEEP_PROBE" in prompt:
    m = re.search(r"MARKER=([^\\s]+)", prompt)
    marker_path = Path(m.group(1)) if m else Path("post_cancel_marker.txt")
    if "--output-format" in args and "stream-json" in args:
        print(json.dumps({{"event": "init", "conversation_id": cid, "init": {{"model": "m"}}}}),
              flush=True)
        print(json.dumps({{"event": "step_update",
                           "step_update": {{"step_type": "agent_response",
                                           "text_delta": "Running slow task... "}}}}),
              flush=True)
        time.sleep(0.8)
        marker_path.write_text("SIDE_EFFECT_EXECUTED\\n", encoding="utf-8")
        print(json.dumps({{"event": "result",
                           "result": {{"status": "SUCCESS", "conversation_id": cid,
                                       "response": "Running slow task... done."}}}}), flush=True)
    sys.exit(0)

reply = "Acknowledged."
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
    # Part A: Genuine cancel against unmodified IsolatedServer -> passed=True
    camp_ok = tmp_path / "camp_cb03_ok"
    with IsolatedServer(tmp_dir=tmp_path / "srv_cb03_ok", mock_agy_script=cb03_agy_script) as srv:
        res_ok = run_scenario(
            case_id="CB-03",
            campaign_dir=camp_ok,
            state=_make_state(camp_ok, srv.base_url),
            target_url=srv.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_ok is not None
        rec_ok, _ = res_ok
        assert rec_ok.passed is True, rec_ok.error_summary
        assert rec_ok.assertions["interrupt_endpoint_200"] is True
        assert rec_ok.assertions["interrupt_acknowledged"] is True
        assert rec_ok.assertions["assistant_message_interrupted"] is True
        assert rec_ok.assertions["zero_post_cancel_side_effects"] is True

    # Part B: Broken /interrupt returning 200 {"interrupted": False} while task finishes "done"
    camp_bad = tmp_path / "camp_cb03_bad"
    with IsolatedServer(tmp_dir=tmp_path / "srv_cb03_bad", mock_agy_script=cb03_agy_script) as srv2:
        orig_async_client_cls = httpx.AsyncClient

        class _BrokenInterruptClient(httpx.AsyncClient):
            async def post(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
                if str(url).endswith("/api/v1/threads/thr_bot_chief/interrupt"):
                    return httpx.Response(
                        200,
                        json={"interrupted": False, "thread_id": "thr_bot_chief"},
                        request=httpx.Request("POST", f"{srv2.base_url}{url}"),
                    )
                return await super().post(url, *args, **kwargs)

        def _client_with_broken_interrupt(self: Any, **kw: Any) -> httpx.AsyncClient:
            from src.qa.scenarios._common import build_auth_headers

            return _BrokenInterruptClient(
                base_url=self.target_url,
                headers=build_auth_headers(self.token),
                timeout=kw.get("timeout", 25.0),
                trust_env=False,
                follow_redirects=False,
            )

        monkeypatch.setattr(
            "src.qa.scenarios._common.ScenarioContext.async_client",
            _client_with_broken_interrupt,
        )
        # Wait long enough for the 0.8s mock_agy task to settle into status='done'
        orig_sleep = __import__("asyncio").sleep

        async def _longer_sleep(delay: float, *a: Any, **kw: Any) -> Any:
            return await orig_sleep(1.1 if delay == 0.4 else delay, *a, **kw)

        monkeypatch.setattr("src.qa.scenarios.cb_03.asyncio.sleep", _longer_sleep)

        res_bad = run_scenario(
            case_id="CB-03",
            campaign_dir=camp_bad,
            state=_make_state(camp_bad, srv2.base_url),
            target_url=srv2.base_url,
            repo_root=_REPO_ROOT,
        )
        assert res_bad is not None
        rec_bad, _ = res_bad
        assert rec_bad.passed is False
        assert rec_bad.assertions["interrupt_endpoint_200"] is True
        assert rec_bad.assertions["interrupt_acknowledged"] is False
        assert rec_bad.assertions["assistant_message_interrupted"] is False
        assert rec_bad.assertions["zero_post_cancel_side_effects"] is False
        assert orig_async_client_cls is httpx.AsyncClient


@pytest.mark.n2
def test_t5_w4_int_cb01_w4_markdown_constructs_pass_playwright(tmp_path: Path) -> None:
    """CB-01 passes Playwright on balanced URL parens, ~strike~, shortcut reflink & \\`*...*\\`."""
    variants = [
        ("url_with_parens", "[CB-01 Valve](https://example.local/Valve_(104)) OK"),
        ("single_tilde_strike", "~old~ CB-01 OK"),
        ("shortcut_reflink", "[CB-01] OK\n\n[CB-01]: https://example.local"),
        ("escaped_backtick_emph", r"\`*CB-01*\` OK"),
    ]
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_w4_{label}.txt"
        reply_file.write_text(reply_body, encoding="utf-8")
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_w4_{label}"
        with IsolatedServer(
            tmp_dir=tmp_path / f"srv_cb01_w4_{label}",
            mock_agy_script=script,
        ) as srv:
            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True


@pytest.mark.n2
def test_t5_w5_int_cb01_w5_markdown_constructs_pass_playwright(tmp_path: Path) -> None:
    """CB-01 passes Playwright on ATX closing #, list heading, entity, bq fence & dunder."""
    variants = [
        ("atx_closing_hashes", "## CB-01 Status ##\nBody OK"),
        ("list_heading", "- ### CB-01 Heading\nBody OK"),
        ("html_entity", "CB-01 &amp; OK"),
        ("blockquote_fence", "> ```\n> **CB-01**\n> ```"),
        ("intraword_dunder", "foo__bar__baz CB-01"),
    ]
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_w5_{label}.txt"
        reply_file.write_text(reply_body, encoding="utf-8")
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_w5_{label}"
        with IsolatedServer(
            tmp_dir=tmp_path / f"srv_cb01_w5_{label}",
            mock_agy_script=script,
        ) as srv:
            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True


@pytest.mark.n2
def test_t5_w6_int_cb01_intraword_star_and_reflinks_pass_playwright(tmp_path: Path) -> None:
    """CB-01 passes Playwright on intraword `*`, undefined `[CB-01][]`, and defined `[CB-01][]`."""
    variants = [
        ("intraword_star", "foo*bar*baz CB-01"),
        ("undefined_collapsed_reflink", "[CB-01][] OK"),
        ("undefined_full_reflink", "[CB-01][missing] OK"),
        ("defined_collapsed_reflink", "[CB-01][] OK\n\n[CB-01]: https://example.local"),
    ]
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_w6_{label}.txt"
        reply_file.write_text(reply_body, encoding="utf-8")
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_w6_{label}"
        with IsolatedServer(
            tmp_dir=tmp_path / f"srv_cb01_w6_{label}",
            mock_agy_script=script,
        ) as srv:
            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True


@pytest.mark.n2
def test_t5_w7_int_cb01_footnotes_table_pipes_and_list_bq_pass_playwright(
    tmp_path: Path,
) -> None:
    """CB-01 passes Playwright on GFM footnotes, table pipes (`\\|` & code), and `- > ...`."""
    variants = [
        ("footnote_ref", "CB-01 OK[^1]\n\n[^1]: note"),
        ("table_code_pipe", "| `a | b` | C |\n| --- | --- |\n| 1 | 2 |"),
        ("table_escaped_pipe", r"| A \| B | C |" + "\n| --- | --- |\n| 1 | 2 |"),
        ("list_then_bq", "- > CB-01 OK"),
    ]
    for label, reply_body in variants:
        reply_file = tmp_path / f"reply_w7_{label}.txt"
        reply_file.write_text(reply_body, encoding="utf-8")
        reply_path_lit = json.dumps(str(reply_file))
        script = f"""#!/usr/bin/env python3
import json, sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

reply = Path({reply_path_lit}).read_text(encoding="utf-8")
cid = "{_CONV_ID}"
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
        camp = tmp_path / f"camp_cb01_w7_{label}"
        with IsolatedServer(
            tmp_dir=tmp_path / f"srv_cb01_w7_{label}",
            mock_agy_script=script,
        ) as srv:
            res = run_scenario(
                case_id="CB-01",
                campaign_dir=camp,
                state=_make_state(camp, srv.base_url),
                target_url=srv.base_url,
                repo_root=_REPO_ROOT,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is True, f"{label}: {rec.error_summary}"
            assert rec.assertions["ui_assistant_reply_visible"] is True
            assert rec.assertions["ui_thread_switch_and_reload_persisted"] is True
            assert rec.assertions["browser_clean"] is True
