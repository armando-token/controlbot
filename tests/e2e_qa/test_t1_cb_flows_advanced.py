"""Tier 1 isolated happy-path E2E tests for advanced flows CB-07..CB-13 and QA-5."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import re
import socket
import sqlite3
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from tests.e2e._helpers import LabStack
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    build_cb10_three_deliverables_spec,
    evaluate_csv_to_json_converter,
)
from tests.e2e_qa.helpers import (
    IsolatedQAEnv,
    QACliRunner,
    SseFrame,
    alloc_qa_free_port,
    assert_no_secret_leak,
    iter_sse_events,
    trigger_and_wait_turn,
)

pytestmark = pytest.mark.qa_tier1

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONV_ID = "22222222-3333-4444-5555-666666666666"

_ADVANCED_MOCK_AGY_SCRIPT = r"""#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, arg in enumerate(args):
    if arg == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break
    if arg.startswith("--prompt="):
        prompt = arg.split("=", 1)[1]
        break

cid = "__CONV_ID__"
reply = "Resumed mock agy reply after approval."
cwd = Path.cwd()

# CB-09: write real CSV -> JSON converter + unit tests in project workspace
if "CB09_CSV_PROJECT" in prompt:
    proj = cwd / "cb09_proj"
    proj.mkdir(parents=True, exist_ok=True)
    converter_code = '''import csv
import json
import sys
from pathlib import Path


def convert_csv_to_json(csv_path: Path, out_path: Path) -> list[dict[str, str]]:
    raw = csv_path.read_text(encoding="utf-8")
    if raw.count('"') % 2 != 0:
        raise ValueError("Unterminated double quote in CSV")
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = [row for row in csv.reader(fh) if any(cell.strip() for cell in row)]
    if not rows:
        raise ValueError("Empty CSV")
    header = rows[0]
    records: list[dict[str, str]] = []
    for row in rows[1:]:
        if len(row) != len(header):
            raise ValueError(f"Ragged row width: {len(row)} != {len(header)}")
        records.append(dict(zip(header, row, strict=True)))
    out_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    return records


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: csv_to_json.py <input.csv> <output.json>\\n")
        return 2
    try:
        convert_csv_to_json(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        sys.stderr.write(f"CSV error: {exc}\\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    test_code = '''from pathlib import Path
from csv_to_json import convert_csv_to_json


def test_converter_handles_quotes_and_utf8(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    dst = tmp_path / "out.json"
    q = chr(34)
    src.write_text(f"sku,name,qty\\n\\nCB-1,{q}Valve, {q}{q}A{q}{q}{q},5\\n", encoding="utf-8")
    rows = convert_csv_to_json(src, dst)
    assert rows == [{"sku": "CB-1", "name": f"Valve, {q}A{q}", "qty": "5"}]
'''
    (proj / "csv_to_json.py").write_text(converter_code, encoding="utf-8")
    (proj / "test_csv_to_json.py").write_text(test_code, encoding="utf-8")
    reply = f"CB-09 project created at {proj} with csv_to_json.py and test_csv_to_json.py."

# CB-10: two-agent 3-deliverable handoff project
elif "CB10_COLLAB" in prompt:
    proj = cwd / "cb10_summary_pkg"
    (proj / "src_pkg").mkdir(parents=True, exist_ok=True)
    (proj / "tests").mkdir(parents=True, exist_ok=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    if "AGENT_ALPHA" in prompt and "[CHANNEL HANDOFF CONTEXT]" not in prompt:
        (proj / "src_pkg" / "calc.py").write_text(
            "def compute_summary(values: list[float]) -> dict[str, float]:\n"
            "    if not values:\n"
            "        raise ValueError('values must not be empty')\n"
            "    total = float(sum(values))\n"
            "    return {'count': float(len(values)), 'sum': total, 'avg': total / len(values)}\n",
            encoding="utf-8",
        )
        reply = "D1 delivered: src_pkg/calc.py implements compute_summary."
    else:
        (proj / "src_pkg" / "cli.py").write_text(
            "import json\n"
            "import sys\n"
            "from src_pkg.calc import compute_summary\n\n\n"
            "def main(argv: list[str] | None = None) -> int:\n"
            "    raw = argv if argv is not None else sys.argv[1:]\n"
            "    nums = [float(x) for x in raw]\n"
            "    print(json.dumps(compute_summary(nums), sort_keys=True))\n"
            "    return 0\n",
            encoding="utf-8",
        )
        (proj / "tests" / "test_calc_cli.py").write_text(
            "import json\n"
            "from src_pkg.calc import compute_summary\n"
            "from src_pkg.cli import main\n\n\n"
            "def test_summary_cli_roundtrip(capsys) -> None:\n"
            "    assert compute_summary([2.0, 4.0])['avg'] == 3.0\n"
            "    rc = main(['2', '4', '6'])\n"
            "    assert rc == 0\n"
            "    out = json.loads(capsys.readouterr().out)\n"
            "    assert out == {'avg': 4.0, 'count': 3.0, 'sum': 12.0}\n",
            encoding="utf-8",
        )
        reply = "D2 and D3 delivered: src_pkg/cli.py and tests/test_calc_cli.py integrated."

elif "CONCURRENT_TAG=" in prompt:
    m = re.search(r"CONCURRENT_TAG=([A-Za-z0-9_-]+)", prompt)
    tag = m.group(1) if m else "UNKNOWN"
    reply = f"Concurrent reply isolated for {tag}."

if "--output-format" in args and "stream-json" in args:
    print(json.dumps({
        "event": "init",
        "conversation_id": cid,
        "init": {"model": "gemini-4-carbon-low"},
    }), flush=True)
    print(json.dumps({
        "event": "step_update",
        "step_update": {
            "step_type": "agent_response",
            "text_delta": reply,
        },
    }), flush=True)
    print(json.dumps({
        "event": "result",
        "result": {
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": reply,
        },
    }), flush=True)
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": reply}))
""".replace("__CONV_ID__", _CONV_ID)


class _NoSignalUvicornServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


@asynccontextmanager
async def _run_loopback_app(app: FastAPI) -> AsyncIterator[str]:
    port = alloc_qa_free_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(128)
    sock.setblocking(False)
    srv = _NoSignalUvicornServer(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
    )
    task = asyncio.create_task(srv.serve(sockets=[sock]))
    try:
        deadline = asyncio.get_running_loop().time() + 10.0
        while not srv.started:
            if task.done():
                raise RuntimeError(f"Webhook sink exited early: {task.exception()!r}")
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Timed out starting webhook sink")
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(task, timeout=5.0)
        with contextlib.suppress(OSError):
            sock.close()


async def _poll_task_until_terminal(
    aclient: httpx.AsyncClient,
    run_id: str,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        resp = await aclient.get(f"/api/tasks/{run_id}")
        assert resp.status_code == 200
        snap: dict[str, Any] = resp.json()
        status = snap["run"]["status"]
        if status in {"succeeded", "partial", "failed", "cancelled", "waiting_for_input"}:
            return snap
        await asyncio.sleep(0.15)
    raise TimeoutError(f"Task {run_id} did not settle within {timeout}s")


def _load_megaplan_run_records(camp_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "qa_run_records" in tables:
                for row in conn.execute("SELECT * FROM qa_run_records").fetchall():
                    row_dict = dict(row)
                    payload_raw = row_dict.get("payload_json")
                    if isinstance(payload_raw, str) and payload_raw.strip():
                        parsed = json.loads(payload_raw)
                        if isinstance(parsed, dict):
                            row_dict = {**row_dict, **parsed}
                    records.append(row_dict)
    if records:
        return records

    for run_file in sorted([*camp_dir.glob("**/run_*.json"), *camp_dir.glob("**/runs.jsonl")]):
        raw_text = run_file.read_text(encoding="utf-8")
        if run_file.suffix == ".jsonl":
            for line in raw_text.splitlines():
                if line.strip():
                    records.append(json.loads(line))
        else:
            records.append(json.loads(raw_text))
    return records


# ---------------------------------------------------------------------------
# CB-07: Approvals, EffectSim Idempotency & Webhook Draft Delivery
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb07_approval_card_deny_zero_effects_and_allow_once_ui_recovery(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-07: ApprovalCard pauses pre-effect, Deny leaves 0 effects, Allow recovers cleanly."""
    env = qa_env_factory(
        with_lab=True,
        mock_agy_script=_ADVANCED_MOCK_AGY_SCRIPT,
        name="cb07_appr_ui",
    )
    assert env.lab_stack is not None
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Trigger /approval -> Deny -> 0 applied effects in effect_sim
    await composer.fill("/approval Flush reactor standby valve")
    await composer.press("Enter")
    deny_card = page.locator("div.my-2\\.5").filter(
        has_text="Flush reactor standby valve"
    ).first
    await deny_card.get_by_text("Needs approval").wait_for(state="visible")
    await deny_card.get_by_role("button", name="Deny").click()
    await deny_card.get_by_text("Denied").wait_for(state="visible")

    with httpx.Client(timeout=10.0) as lab_client:
        state_before = lab_client.get(f"{env.lab_stack.effect_sim_url}/api/effects/state").json()
        assert state_before["total_applied"] == 0

    # 2. Trigger seeded ask_first approval -> Allow -> visible recovery reply
    await composer.fill("Please delete files in temp workspace")
    await composer.press("Enter")
    ask_card = page.locator("div.my-2\\.5").filter(
        has_text="Ask before deleting files"
    ).first
    await ask_card.get_by_text("Needs approval").wait_for(state="visible")
    await ask_card.get_by_role("button", name="Allow", exact=True).click()
    await ask_card.get_by_text("Allowed once").wait_for(state="visible")
    await page.get_by_text("Resumed mock agy reply after approval.").wait_for(
        state="visible", timeout=10000
    )

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb07_effect_sim_idempotency_and_fail_after_apply_reconciliation(
    qa_lab_env: IsolatedQAEnv,
) -> None:
    """CB-07: EffectSim applies once per operation_key, deduplicates replays & reconciles 500."""
    assert qa_lab_env.lab_stack is not None
    effect_url = qa_lab_env.lab_stack.effect_sim_url

    async with qa_lab_env.async_client(timeout=35.0) as aclient:
        # 1. First effect application -> total_applied == 1
        r1 = await aclient.post(
            "/api/tasks",
            json={
                "query": "Apply effect operation_key=cb07-op-alpha reset_latch on bomba-34-a1",
                "facility_id": "facility-a",
                "allowed_areas": ["area-1"],
                "allowed_tools": ["effect.apply", "effect.inspect_state"],
                "read_only": False,
            },
        )
        assert r1.status_code == 201, r1.text
        snap1 = await _poll_task_until_terminal(aclient, str(r1.json()["run_id"]))
        assert snap1["run"]["status"] == "succeeded"

        state_1 = (await aclient.get(f"{effect_url}/api/effects/state")).json()
        assert state_1["total_applied"] == 1
        applied_effect = state_1["effects"][0]
        applied_key = str(applied_effect["idempotency_key"])

        # 2. Replay exact idempotency_key -> deduplicated, total_applied stays 1
        replay_resp = await aclient.post(
            f"{effect_url}/api/effects/apply",
            json={
                "idempotency_key": applied_key,
                "asset_id": applied_effect["asset_id"],
                "action": applied_effect["action"],
                "params": applied_effect["params"],
            },
        )
        assert replay_resp.status_code == 200
        assert replay_resp.json()["deduplicated"] is True

        state_2 = (await aclient.get(f"{effect_url}/api/effects/state")).json()
        assert state_2["total_applied"] == 1
        assert state_2["deduplicated_hits"] >= 1

        # 3. fail_after_apply=true reconciles/retries cleanly without duplicating applied count
        r3 = await aclient.post(
            "/api/tasks",
            json={
                "query": (
                    "Apply effect operation_key=cb07-op-beta "
                    "fail_after_apply=true reset_latch on bomba-34-a1"
                ),
                "facility_id": "facility-a",
                "allowed_areas": ["area-1"],
                "allowed_tools": ["effect.apply", "effect.inspect_state"],
                "read_only": False,
            },
        )
        assert r3.status_code == 201
        snap3 = await _poll_task_until_terminal(aclient, str(r3.json()["run_id"]))
        assert snap3["run"]["status"] in {"succeeded", "failed"}
        state_3 = (await aclient.get(f"{effect_url}/api/effects/state")).json()
        assert state_3["total_applied"] == 2


@pytest.mark.qa_existing
async def test_cb07_editable_draft_card_loopback_webhook_hmac_delivery(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-07: EditableDraftCard edits & delivers signed HMAC webhook to loopback receiver."""
    received: list[dict[str, Any]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def receive_hook(request: Request) -> JSONResponse:
        raw_body = await request.body()
        received.append(
            {
                "signature": request.headers.get("x-controlbot-signature", ""),
                "raw": raw_body,
                "json": json.loads(raw_body.decode("utf-8")),
            }
        )
        return JSONResponse({"ok": True})

    env = qa_env_factory(
        extra_env={"GROKBOT_ALLOW_LOOPBACK_WEBHOOKS": "1"},
        name="cb07_webhook",
    )
    async with _run_loopback_app(wh_app) as wh_origin:
        with env.client() as client:
            create_resp = client.post(
                "/api/v1/drafts",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "channel_type": "webhook",
                    "fields": {
                        "webhook_url": f"{wh_origin}/hook",
                        "webhook_secret": "cb07-hmac-secret",
                        "subject": "Shift Alert",
                        "body": "Initial body",
                    },
                },
            )
            assert create_resp.status_code == 201
            draft_id = str(create_resp.json()["id"])

        page = strict_browser_page.page
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        draft_card = page.locator("div.my-2\\.5").filter(
            has_text=re.compile(r"webhook draft", re.I)
        ).first
        await draft_card.get_by_text("Needs approval").wait_for(state="visible", timeout=10000)
        await draft_card.get_by_label("Body").fill("Verified CB-07 payload")
        await draft_card.get_by_role("button", name="Send").click()
        await draft_card.get_by_text("Sent").wait_for(state="visible", timeout=10000)

        assert len(received) == 1
        expected_sig = (
            "sha256="
            + hmac.new(b"cb07-hmac-secret", received[0]["raw"], hashlib.sha256).hexdigest()
        )
        assert received[0]["signature"] == expected_sig
        assert received[0]["json"]["draft_id"] == draft_id
        assert received[0]["json"]["fields"]["body"] == "Verified CB-07 payload"
        assert_no_secret_leak(received[0]["json"], secrets=("cb07-hmac-secret",))

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# CB-08: Settings Persistence, 5-Scope Memory Isolation & Routines
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb08_settings_persistence_across_reload(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-08: Settings & Connected Apps preferences persist across browser reload."""
    page = strict_browser_page.page
    await page.goto(qa_env.base_url + "/app", wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")

    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    await dlg.get_by_role("button", name="Dark", exact=True).click()
    await dlg.get_by_label("Display name").fill("Reliability Lead")
    await dlg.get_by_label("Default thinking level").select_option("high")
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")

    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    assert await page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"

    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    assert await dlg.get_by_label("Display name").input_value() == "Reliability Lead"
    assert await dlg.get_by_label("Default thinking level").input_value() == "high"
    await dlg.get_by_role("button", name="Light", exact=True).click()
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
def test_cb08_five_scope_memory_isolation_and_fts_delete_purge(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-08: 5-scope memory isolation, secret-redacted export & FTS delete purge."""
    canary_secret = "sk-qa-cb08-secret-9876543210abcdef"
    with qa_env.client() as client:
        # 1. user scope isolation
        r_user_a = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "op_alpha"},
            json={
                "scope": "user",
                "scope_id": "op_alpha",
                "kind": "preference",
                "title": "Alpha User Pref",
                "content": f"Credential: {canary_secret}",
            },
        )
        assert r_user_a.status_code == 201, r_user_a.text
        alpha_id = str(r_user_a.json()["id"])

        # 2. agent_role scope isolation
        r_role = client.post(
            "/api/v1/memory",
            headers={"X-Agent-Role": "scada_reviewer"},
            json={
                "scope": "agent_role",
                "scope_id": "scada_reviewer",
                "kind": "preference",
                "title": "Role Checklist",
                "content": "Verify calibration tags",
            },
        )
        assert r_role.status_code == 201, r_role.text

        # 3. thread scope isolation
        r_thr = client.post(
            "/api/v1/memory",
            headers={"X-Thread-Id": "thr_scope_1"},
            json={
                "scope": "thread",
                "scope_id": "thr_scope_1",
                "kind": "dated_observation",
                "title": "Thread Note",
                "content": "UniqueThreadToken",
                "observed_at": "2026-11-27T00:00:00Z",
                "valid_until": "2026-12-31T23:59:59Z",
            },
        )
        assert r_thr.status_code == 201, r_thr.text

        # 4. project_area scope isolation
        r_proj = client.post(
            "/api/v1/memory",
            headers={"X-Project-Area": "area_turbines"},
            json={
                "scope": "project_area",
                "scope_id": "area_turbines",
                "kind": "source_reference",
                "title": "Turbine Area Rule",
                "content": "Max RPM 3600",
            },
        )
        assert r_proj.status_code == 201, r_proj.text

        # 5. org_approved scope (requires Manager role for approved_procedure)
        r_org = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "org",
                "kind": "approved_procedure",
                "title": "Org Lockout SOP",
                "content": "Always isolate power first.",
            },
        )
        assert r_org.status_code == 201, r_org.text

        # Cross-scope isolation assertions
        user_b_items = client.get(
            "/api/v1/memory",
            params={"scope": "user"},
            headers={"X-User-Id": "op_beta"},
        ).json()["items"]
        assert all(it["id"] != alpha_id for it in user_b_items)

        other_role_items = client.get(
            "/api/v1/memory",
            params={"scope": "agent_role"},
            headers={"X-Agent-Role": "other_role"},
        ).json()["items"]
        assert all(it["title"] != "Role Checklist" for it in other_role_items)

        other_thr_items = client.get(
            "/api/v1/memory",
            params={"scope": "thread"},
            headers={"X-Thread-Id": "thr_scope_2"},
        ).json()["items"]
        assert all(it["title"] != "Thread Note" for it in other_thr_items)

        other_proj_items = client.get(
            "/api/v1/memory",
            params={"scope": "project_area"},
            headers={"X-Project-Area": "area_boilers"},
        ).json()["items"]
        assert all(it["title"] != "Turbine Area Rule" for it in other_proj_items)

        # Export redacts secrets
        exp_json = client.get(
            "/api/v1/memory/export",
            params={"format": "json"},
            headers={"X-User-Id": "op_alpha"},
        )
        assert exp_json.status_code == 200
        assert_no_secret_leak(exp_json.json(), secrets=(canary_secret,))

        exp_md = client.get(
            "/api/v1/memory/export",
            params={"format": "md"},
            headers={"X-User-Id": "op_alpha"},
        )
        assert exp_md.status_code == 200
        assert 'filename="memory_export.md"' in exp_md.headers.get("Content-Disposition", "")
        assert_no_secret_leak(exp_md.text, secrets=(canary_secret,))

        # Delete & verify FTS purge
        del_resp = client.delete(
            f"/api/v1/memory/{alpha_id}",
            headers={"X-User-Id": "op_alpha"},
        )
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] is True

        fts_after = client.get(
            "/api/v1/memory",
            params={"q": "Alpha User Pref"},
            headers={"X-User-Id": "op_alpha"},
        ).json()["items"]
        assert all(it["id"] != alpha_id for it in fts_after)


@pytest.mark.qa_existing
async def test_cb08_routine_synthetic_firing_and_run_history(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-08: Routine creation, manual test + webhook firing & RoutineRun history persist."""
    env = qa_env_factory(mock_agy_script=_ADVANCED_MOCK_AGY_SCRIPT, name="cb08_routines")
    with env.client() as client:
        create = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Pump Check Routine",
                "instruction": "Check pump vibration",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        assert create.status_code == 201, create.text
        routine = create.json()
        rid = str(routine["id"])
        webhook_key = str(routine["webhook_key"])

        t_resp = client.post(f"/api/v1/routines/{rid}/test")
        assert t_resp.status_code == 202

        w_resp = client.post(
            f"/api/v1/webhooks/routines/{rid}",
            headers={"Authorization": f"Bearer {webhook_key}"},
            json={"event": "cb08_synthetic"},
        )
        assert w_resp.status_code == 202

        deadline = asyncio.get_running_loop().time() + 10.0
        runs: list[dict[str, Any]] = []
        while asyncio.get_running_loop().time() < deadline:
            runs_resp = client.get(f"/api/v1/routines/{rid}/runs")
            assert runs_resp.status_code == 200
            runs = runs_resp.json()["runs"]
            if len(runs) >= 2 and all(r.get("status") != "running" for r in runs):
                break
            await asyncio.sleep(0.15)
        assert len(runs) >= 2
        sources = {str(r.get("trigger")) for r in runs}
        assert "manual" in sources
        assert "webhook" in sources

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_text("Pump Check Routine", exact=True).wait_for(state="visible")
    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# CB-09: Small Code Project (CSV -> JSON) + Independent Evaluator
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb09_csv_to_json_workspace_and_independent_evaluator(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    tmp_path: Path,
) -> None:
    """CB-09: CSV->JSON project + tests in workspace pass independent edge-case evaluator."""
    env = qa_env_factory(mock_agy_script=_ADVANCED_MOCK_AGY_SCRIPT, name="cb09_csv")
    async with env.async_client(timeout=30.0) as aclient:
        patch_resp = await aclient.patch(
            "/api/v1/bots/bot_chief",
            json={"project_name": "Grokbotclon"},
        )
        assert patch_resp.status_code == 200

        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "CB09_CSV_PROJECT Create a CSV to JSON converter and unit tests",
            timeout=25.0,
        )
        assert turn.assistant_message is not None

    proj_dir = env.projects_root / "Grokbotclon" / "cb09_proj"
    converter_path = proj_dir / "csv_to_json.py"
    test_path = proj_dir / "test_csv_to_json.py"
    assert converter_path.is_file()
    assert test_path.is_file()

    report = evaluate_csv_to_json_converter(
        [sys.executable, str(converter_path)],
        work_dir=tmp_path / "cb09_eval_work",
        test_cmd=[sys.executable, "-m", "pytest", "-q", str(test_path)],
    )
    assert report.passed is True, f"CB-09 independent evaluation failed: {report}"
    assert report.project_tests_passed is True
    assert len(report.sample_results) == 4
    assert all(res.passed for res in report.sample_results)


@pytest.mark.qa_megaplan
def test_megaplan_cb09_scan_evaluates_csv_to_json_project(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #21: `python -m src.qa scan --cases CB-09` evaluates CSV->JSON independently."""
    camp_dir = tmp_path / "camp_cb09"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-09", "--json"]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined
    assert "notimplementederror" not in combined, (
        f"CB-09 scenario scan is not yet implemented: {scan_res.stderr}"
    )
    assert scan_res.returncode == 0
    records = _load_megaplan_run_records(camp_dir)
    cb09 = [r for r in records if r.get("case_id") == "CB-09"]
    assert cb09 and cb09[0]["passed"] is True


# ---------------------------------------------------------------------------
# CB-10: Two-Agent Multi-File 3-Deliverable Project & Handoff Attribution
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb10_two_agent_three_deliverables_handoff_attribution_and_build(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-10: 2 agents collaborate on 3 deliverables with handoff attribution & passing build."""
    spec = build_cb10_three_deliverables_spec()
    env = qa_env_factory(mock_agy_script=_ADVANCED_MOCK_AGY_SCRIPT, name="cb10_multiagent")

    async with env.async_client(timeout=35.0) as aclient:
        b1 = await aclient.post(
            "/api/v1/bots",
            json={
                "name": "agent_alpha",
                "engine_id": "agy",
                "project_name": "Grokbotclon",
            },
        )
        b2 = await aclient.post(
            "/api/v1/bots",
            json={
                "name": "agent_beta",
                "engine_id": "agy",
                "project_name": "Grokbotclon",
            },
        )
        assert b1.status_code == 201 and b2.status_code == 201
        alpha_id = str(b1.json()["id"])
        beta_id = str(b2.json()["id"])

        ch_resp = await aclient.post(
            "/api/v1/channels",
            json={"name": "CB10 Collab", "bot_ids": [alpha_id, beta_id]},
        )
        assert ch_resp.status_code == 201
        thread_id = str(ch_resp.json()["thread_id"])

        # Turn 1: target ONLY @agent_alpha -> verifies intermediate D1-only disk attribution
        collab_prompt_body = (
            "CB10_COLLAB AGENT_ALPHA build D1 calc.py, "
            "then agent_beta integrate D2 cli.py and D3 tests/test_calc_cli.py"
        )
        turn1 = await trigger_and_wait_turn(
            aclient,
            thread_id,
            f"@agent_alpha {collab_prompt_body}",
            timeout=25.0,
        )
        assert turn1.assistant_message is not None
        assert turn1.assistant_message["sender_bot_id"] == alpha_id
        assert not any(
            (f.event_type or f.event) == "handoff.dispatched" for f in turn1.events
        )
        t1_msgs = (await aclient.get(f"/api/v1/threads/{thread_id}/messages")).json()["messages"]
        assert [str(m["sender_bot_id"]) for m in t1_msgs if m["sender_type"] == "bot"] == [
            alpha_id
        ]

        proj_root = env.projects_root / "Grokbotclon" / spec.project_name
        d1, d2, d3 = spec.deliverables
        assert (proj_root / d1.rel_path).is_file(), (
            f"Missing D1 after agent_alpha turn: {proj_root / d1.rel_path}"
        )
        d1_text = (proj_root / d1.rel_path).read_text(encoding="utf-8")
        for sym in d1.required_symbols:
            assert sym in d1_text, f"Missing symbol {sym!r} in {proj_root / d1.rel_path}"
        assert not (proj_root / d2.rel_path).exists(), (
            f"D2 ({d2.rel_path}) must not exist before agent_beta turn"
        )
        assert not (proj_root / d3.rel_path).exists(), (
            f"D3 ({d3.rel_path}) must not exist before agent_beta turn"
        )

        # Turn 2: @all triggers agent_alpha -> handoff.dispatched -> agent_beta (D2 & D3)
        frames: list[SseFrame] = []
        sse_connected = asyncio.Event()
        turn2_ready = asyncio.Event()
        turn2_holder: dict[str, str] = {}

        async def _listen_collab() -> None:
            completed_bots: set[str] = set()
            async for frame in iter_sse_events(
                aclient,
                timeout=30.0,
                on_connected=sse_connected,
            ):
                frames.append(frame)
                if not turn2_ready.is_set():
                    await turn2_ready.wait()
                ev = frame.event_type or frame.event
                if (
                    ev == "message.completed"
                    and isinstance(frame.data, dict)
                    and frame.data.get("thread_id") == thread_id
                    and frame.data.get("turn_id") == turn2_holder["id"]
                ):
                    msg = frame.data.get("payload", {}).get("message", {})
                    if msg.get("sender_bot_id"):
                        completed_bots.add(str(msg["sender_bot_id"]))
                    if {alpha_id, beta_id}.issubset(completed_bots):
                        return

        listen_task = asyncio.create_task(_listen_collab())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            post_resp = await aclient.post(
                f"/api/v1/threads/{thread_id}/messages",
                json={"content": f"@all {collab_prompt_body}"},
            )
            assert post_resp.status_code == 202
            turn2_id = str(post_resp.json()["turn_id"])
            turn2_holder["id"] = turn2_id
            turn2_ready.set()
            await asyncio.wait_for(listen_task, timeout=30.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task

        handoffs = [
            f
            for f in frames
            if (f.event_type or f.event) == "handoff.dispatched"
            and isinstance(f.data, dict)
            and f.data.get("thread_id") == thread_id
            and f.data.get("turn_id") == turn2_id
        ]
        assert len(handoffs) == 1, f"Expected 1 handoff.dispatched in Turn 2, got {handoffs!r}"
        h_data = handoffs[0].data
        assert isinstance(h_data, dict)
        assert h_data.get("bot_id") == beta_id
        h_payload = h_data.get("payload")
        assert isinstance(h_payload, dict)
        assert h_payload.get("from_bot_id") == alpha_id
        assert h_payload.get("to_bot_id") == beta_id
        assert h_payload.get("from_name") == "agent_alpha"
        assert h_payload.get("to_name") == "agent_beta"
        assert "D1 delivered" in str(h_payload.get("summary", ""))

        msgs = (await aclient.get(f"/api/v1/threads/{thread_id}/messages")).json()["messages"]
        bot_senders = [str(m["sender_bot_id"]) for m in msgs if m["sender_type"] == "bot"]
        assert alpha_id in bot_senders
        assert beta_id in bot_senders

    # Verify reopen persistence in Playwright UI
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.locator("aside").get_by_text("CB10 Collab").click()
    await (
        page.get_by_text("D1 delivered: src_pkg/calc.py implements compute_summary.")
        .first.wait_for(state="visible", timeout=10000)
    )
    await (
        page.get_by_text(
            "D2 and D3 delivered: src_pkg/cli.py and tests/test_calc_cli.py integrated."
        )
        .first.wait_for(state="visible", timeout=10000)
    )
    strict_browser_page.assert_clean()

    # Verify real files, symbols, build_command & test_command on disk
    for deliverable in spec.deliverables:
        target = proj_root / deliverable.rel_path
        assert target.is_file(), f"Missing deliverable {deliverable.deliverable_id}: {target}"
        text = target.read_text(encoding="utf-8")
        for sym in deliverable.required_symbols:
            assert sym in text, f"Missing symbol {sym!r} in {target}"

    build_proc = subprocess.run(
        list(spec.build_command),
        cwd=str(proj_root),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert build_proc.returncode == 0, f"CB-10 build failed: {build_proc.stderr}"

    test_proc = subprocess.run(
        list(spec.test_command),
        cwd=str(proj_root),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert test_proc.returncode == 0, f"CB-10 tests failed: {test_proc.stdout}\n{test_proc.stderr}"


@pytest.mark.qa_megaplan
def test_megaplan_cb10_scan_verifies_two_agent_deliverables_and_build(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #22: `python -m src.qa scan --cases CB-10` verifies deliverables & build."""
    camp_dir = tmp_path / "camp_cb10"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0
    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-10", "--json"]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined
    assert "notimplementederror" not in combined, (
        f"CB-10 scenario scan is not yet implemented: {scan_res.stderr}"
    )
    assert scan_res.returncode == 0
    records = _load_megaplan_run_records(camp_dir)
    cb10 = [r for r in records if r.get("case_id") == "CB-10"]
    assert cb10 and cb10[0]["passed"] is True


# ---------------------------------------------------------------------------
# CB-11: SCADA & Maintenance Read-Only Provenance (facility_a & facility_b)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb11_facility_a_pump34_read_only_scada_maintenance_provenance(
    qa_lab_env: IsolatedQAEnv,
) -> None:
    """CB-11: facility_a Pump 34 recovers exact SCADA/CMMS provenance with 0 effect mutations."""
    assert qa_lab_env.lab_stack is not None
    async with qa_lab_env.async_client(timeout=35.0) as aclient:
        patch_resp = await aclient.patch(
            "/api/v1/bots/bot_ops",
            json={"engine_id": "controlbot_runtime"},
        )
        assert patch_resp.status_code == 200

        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_ops",
            "Check bomba 34 alarms and readings in SCADA and maintenance",
            timeout=35.0,
        )
        assert turn.assistant_message is not None
        content = str(turn.assistant_message["content"])
        assert "ALM-3401" in content
        assert "WO-3408" in content
        meta = turn.assistant_message.get("metadata")
        assert isinstance(meta, dict)
        assert meta["verdict"] == "verified"

        effect_state = (
            await aclient.get(f"{qa_lab_env.lab_stack.effect_sim_url}/api/effects/state")
        ).json()
        assert effect_state["total_applied"] == 0


@pytest.mark.qa_existing
async def test_cb11_facility_b_spanish_headers_reordered_columns_and_provenance(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-11: facility_b (bomba-77-b2 / SC-77 / CMMS-77) Spanish headers & timestamps verified."""
    lab = LabStack(fixture_mode="facility_b").start()
    try:
        env = qa_env_factory(
            extra_env={
                **lab.env_vars(),
                "GROKBOT_INSTALLATION_CONFIG": str(
                    _REPO_ROOT / "lab" / "configs" / "facility_b.json"
                ),
            },
            name="cb11_fac_b",
        )
        async with env.async_client(timeout=35.0) as aclient:
            submit = await aclient.post(
                "/api/tasks",
                json={
                    "query": "Check P-77B alarms and latest work order",
                    "facility_id": "facility-b",
                    "allowed_areas": ["area-2"],
                    "read_only": True,
                },
            )
            assert submit.status_code == 201, submit.text
            run_id = str(submit.json()["run_id"])
            snap = await _poll_task_until_terminal(aclient, run_id, timeout=30.0)
            assert snap["run"]["status"] == "succeeded", snap
            result = snap["result"]
            answer = str(result["answer"])
            assert "ALM-7701" in answer
            assert "WO-7705" in answer

            obs = result["verified_observations"]
            assert {o["source"] for o in obs} == {"scada", "maintenance"}
            assert any(
                o["asset_id"] == "SC-77" and (o.get("observed_at") or o.get("source_time"))
                for o in obs
            )
            assert any(
                o["asset_id"] == "CMMS-77" and (o.get("observed_at") or o.get("source_time"))
                for o in obs
            )

            effect_state = (await aclient.get(f"{lab.effect_sim_url}/api/effects/state")).json()
            assert effect_state["total_applied"] == 0
    finally:
        lab.stop()


@pytest.mark.qa_megaplan
def test_megaplan_cb11_scan_executes_scada_cmms_parity(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #23: `python -m src.qa scan --cases CB-11` verifies industrial parity."""
    camp_dir = tmp_path / "camp_cb11"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0
    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-11", "--json"]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined
    assert "notimplementederror" not in combined, (
        f"CB-11 scenario scan is not yet implemented: {scan_res.stderr}"
    )
    assert scan_res.returncode == 0
    records = _load_megaplan_run_records(camp_dir)
    cb11 = [r for r in records if r.get("case_id") == "CB-11"]
    assert cb11 and cb11[0]["passed"] is True


# ---------------------------------------------------------------------------
# CB-12: Operational Variants (SIGTERM Restart WAL/SSE & Concurrent Runs)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb12_server_sigterm_restart_preserves_wal_db_and_sse_epoch(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-12: SIGTERM restart preserves SQLite WAL data, SSE epoch & replays missed events."""
    async with qa_env.async_client() as client:
        bot_resp = await client.post(
            "/api/v1/bots",
            json={"name": "Restart Survivor", "engine_id": "agy"},
        )
        assert bot_resp.status_code == 201
        created_bot_id = str(bot_resp.json()["id"])

        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Restart WAL seed")
        msg_id = str(turn.user_message["id"])

        pre_frames: list[SseFrame] = []
        connected = asyncio.Event()

        async def _collect() -> None:
            async for frame in iter_sse_events(client, timeout=10.0, on_connected=connected):
                if frame.event_type == "message.reaction":
                    pre_frames.append(frame)
                    return

        task = asyncio.create_task(_collect())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "1️⃣", "action": "add"},
            )
            await asyncio.wait_for(task, timeout=10.0)
        finally:
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        anchor_id = str(pre_frames[0].id)
        epoch_before = anchor_id.split("_", 2)[2]
        await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "2️⃣", "action": "add"},
        )

    qa_env.restart(keep_port=False)

    async with qa_env.async_client() as client:
        bots_resp = await client.get("/api/v1/bots")
        assert bots_resp.status_code == 200
        assert any(b["id"] == created_bot_id for b in bots_resp.json()["bots"])

        await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "3️⃣", "action": "add"},
        )
        replayed: list[SseFrame] = []
        async for frame in iter_sse_events(
            client,
            headers={"Last-Event-ID": anchor_id},
            timeout=4.0,
        ):
            replayed.append(frame)
            if (
                frame.event_type == "message.reaction"
                and isinstance(frame.data, dict)
                and frame.data.get("payload", {}).get("emoji") == "3️⃣"
            ):
                break

        assert all(f.event_type != "stream.resync" for f in replayed)
        emojis = [
            f.data.get("payload", {}).get("emoji")
            for f in replayed
            if f.event_type == "message.reaction" and isinstance(f.data, dict)
        ]
        assert emojis == ["2️⃣", "3️⃣"]
        for frame in replayed:
            if frame.id and frame.id.startswith("evt_"):
                assert frame.id.split("_", 2)[2] == epoch_before


@pytest.mark.qa_existing
async def test_cb12_two_concurrent_runs_zero_cross_bleed(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-12: Two concurrent chat turns complete cleanly with zero cross-thread bleed."""
    env = qa_env_factory(mock_agy_script=_ADVANCED_MOCK_AGY_SCRIPT, name="cb12_concurrent")
    async with env.async_client(timeout=35.0) as client:
        turn_a, turn_b = await asyncio.gather(
            trigger_and_wait_turn(
                client,
                "thr_bot_chief",
                "Run CONCURRENT_TAG=RUN_ALPHA_01",
                timeout=25.0,
            ),
            trigger_and_wait_turn(
                client,
                "thr_bot_ops",
                "Run CONCURRENT_TAG=RUN_BETA_02",
                timeout=25.0,
            ),
        )
        assert turn_a.assistant_message is not None
        assert turn_b.assistant_message is not None
        assert "RUN_ALPHA_01" in str(turn_a.assistant_message["content"])
        assert "RUN_BETA_02" not in str(turn_a.assistant_message["content"])
        assert "RUN_BETA_02" in str(turn_b.assistant_message["content"])
        assert "RUN_ALPHA_01" not in str(turn_b.assistant_message["content"])


# ---------------------------------------------------------------------------
# CB-13 / QA-5: Linux Local Without Egress (N3) Honest Verification
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_cb13_n3_probe_strict_and_verify_n3_linux_script_honest_status(
    qa_cli_runner: QACliRunner,
) -> None:
    """CB-13 / QA-5: n3_probe --strict and verify_n3_linux.sh report honest READY vs PENDING."""
    probe_res = qa_cli_runner.run_module("src.n3_probe", ["--json"])
    assert probe_res.returncode in {0, 2}, f"n3_probe failed unexpectedly: {probe_res.stderr}"
    payload = probe_res.json_stdout()
    overall = str(payload["overall_status"])
    assert overall in {"READY", "PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM"}
    assert "linux_os_ready" in payload
    assert "network_isolation_ready" in payload
    assert "local_llm_ready" in payload

    strict_res = qa_cli_runner.run_module("src.n3_probe", ["--strict", "--json"])
    if overall == "READY":
        assert strict_res.returncode == 0
    else:
        assert strict_res.returncode != 0

    script_res = qa_cli_runner.run_command(["bash", "scripts/verify_n3_linux.sh"])
    if overall == "READY":
        assert script_res.returncode == 0
    else:
        # Either exit 2 (active outbound egress) or exit 1 (pending strict probe)
        assert script_res.returncode in {1, 2}


@pytest.mark.qa_megaplan
def test_megaplan_cb12_cb13_qa5_scan_records_variants_and_honest_n3(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #24, #25, #37: `scan --cases CB-12,CB-13` executes CB-12 & honest CB-13."""
    camp_dir = tmp_path / "camp_cb12_13"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-12,CB-13", "--json"]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined
    assert "notimplementederror" not in combined, (
        f"CB-12/CB-13 scenario scan is not yet implemented: {scan_res.stderr}"
    )
    assert "validationerror" not in combined, f"Unexpected ValidationError: {scan_res.stderr}"
    assert "traceback (most recent call last)" not in combined, (
        f"Unhandled traceback in scan:\n{scan_res.stdout}\n{scan_res.stderr}"
    )
    for crash_tok in ("keyerror", "attributeerror", "typeerror", "nameerror"):
        assert crash_tok not in combined, (
            f"Unexpected {crash_tok} crash in scan:\n{scan_res.stdout}\n{scan_res.stderr}"
        )
    assert scan_res.returncode in {0, 1, 2, 3}, (
        f"Unexpected exit code {scan_res.returncode}: {scan_res.stderr}"
    )

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    assert "CB-12" in by_case
    assert "CB-13" in by_case
    assert by_case["CB-12"]["passed"] is True

    n3_probe = qa_cli_runner.run_module("src.n3_probe", ["--json"]).json_stdout()
    if n3_probe["overall_status"] != "READY":
        assert by_case["CB-13"]["passed"] is False, (
            f"CB-13 falsely passed when n3_probe={n3_probe!r}: {by_case['CB-13']!r}"
        )
        assert bool(str(by_case["CB-13"].get("blocked_reason") or "").strip()), (
            f"Expected non-empty blocked_reason for CB-13: {by_case['CB-13']!r}"
        )
    else:
        assert scan_res.returncode == 0
        assert by_case["CB-13"]["passed"] is True
