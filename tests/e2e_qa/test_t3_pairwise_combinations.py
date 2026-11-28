"""Tier 3 pairwise cross-feature combination E2E QA tests across all 10 Megaplan axes."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from playwright.async_api import ConsoleMessage, Page, Response, Route, WebSocket
from src.factory.db import FactoryStore
from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
from src.factory.errors import (
    FactoryLeaseError,
    IsolationBoundaryError,
    PolicyImmutabilityError,
)
from src.factory.models import (
    BacklogItem,
    CandidatePatch,
    CycleBudget,
    compute_proposal_hash,
)
from src.factory.policy import IsolationGuard, PolicyGuard
from tests.e2e._helpers import LabStack, alloc_free_port
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    ValveCatalogFixture,
    build_cb09_csv_samples,
    build_cb10_three_deliverables_spec,
    build_cb_valve_104_catalog,
    build_grok_bot_reference_card,
    evaluate_csv_to_json_converter,
)
from tests.e2e_qa.helpers import (
    FORBIDDEN_PORTS,
    CliResult,
    IsolatedQAEnv,
    QACliRunner,
    SseFrame,
    UxTimingResult,
    alloc_qa_free_port,
    assert_no_secret_leak,
    assert_react_app_surface,
    iter_sse_events,
    measure_ttfp_and_completion,
    trigger_and_wait_turn,
)

pytestmark = pytest.mark.qa_tier3

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEN_MIB = 10 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_CONV_ID = "44444444-5555-6666-7777-888888888888"

_T3_CORE_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import re
import sys
import time
import urllib.request
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

cid = "{_CONV_ID}"
reply = "Tier 3 core mock reply."

if "CANCEL_SLEEP_PROBE" in prompt:
    marker_m = re.search(r"MARKER=([^\\s]+)", prompt)
    marker_path = Path(marker_m.group(1)) if marker_m else Path("t3_cancel_marker.txt")
    if "--output-format" in args and "stream-json" in args:
        print(json.dumps({{
            "event": "init",
            "conversation_id": cid,
            "init": {{"model": "gemini-4-carbon-low"}},
        }}), flush=True)
        print(json.dumps({{
            "event": "step_update",
            "step_update": {{
                "step_type": "agent_response",
                "text_delta": "Running slow T3 task... ",
            }},
        }}), flush=True)
        time.sleep(3.5)
        marker_path.write_text("UNWANTED_T3_POST_CANCEL_WRITE\\n", encoding="utf-8")
        print(json.dumps({{
            "event": "result",
            "result": {{
                "status": "SUCCESS",
                "conversation_id": cid,
                "response": "Running slow T3 task... done.",
            }},
        }}), flush=True)
    sys.exit(0)

if "UX_DELAY_PROBE" in prompt:
    reply = "Tier 3 UX delayed response ready."
    if "--output-format" in args and "stream-json" in args:
        print(json.dumps({{
            "event": "init",
            "conversation_id": cid,
            "init": {{"model": "gemini-4-carbon-low"}},
        }}), flush=True)
        time.sleep(0.35)
        print(json.dumps({{
            "event": "step_update",
            "step_update": {{
                "step_type": "agent_response",
                "text_delta": reply,
            }},
        }}), flush=True)
        print(json.dumps({{
            "event": "result",
            "result": {{
                "status": "SUCCESS",
                "conversation_id": cid,
                "response": reply,
            }},
        }}), flush=True)
        sys.exit(0)

port_match = re.search(r"CATALOG_PORT=(\\d+)", prompt)
if port_match:
    base = f"http://127.0.0.1:{{port_match.group(1)}}"
    with urllib.request.urlopen(base + "/index.json", timeout=5) as resp:
        records = json.loads(resp.read().decode("utf-8"))
    sku_match = re.search(r"SKU=([A-Za-z0-9_-]+)", prompt)
    target_sku = sku_match.group(1) if sku_match else ""
    current = [
        r for r in records if r.get("sku") == target_sku and r.get("status") == "current"
    ]
    if current:
        chosen = current[0]
        with urllib.request.urlopen(base + chosen["source_url"], timeout=5) as page_resp:
            html_body = page_resp.read().decode("utf-8")
        price_m = re.search(r"data-price='([^']+)'", html_body)
        price_val = price_m.group(1) if price_m else chosen["price"]
        reply = (
            f"{{chosen['sku']}}: {{chosen['currency']}} {{price_val}} "
            f"(effective {{chosen['effective_date']}}, source {{chosen['source_url']}})"
        )
    else:
        reply = f"No current catalog price found for {{target_sku}}."
elif any(
    tok in prompt.upper()
    for tok in ("CONTROLBOT_OPS", "CONTROLBOT-OPS", "CONTROLBOT OPS")
):
    reply = "Ops bot targeted reply: telemetry nominal."

if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""

_T3_ADV_MOCK_AGY_SCRIPT = r"""#!/usr/bin/env python3
import json
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
reply = "Tier 3 advanced mock reply."
cwd = Path.cwd()

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


def test_converter_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "sample.csv"
    dst = tmp_path / "sample.json"
    src.write_text("sku,name,qty\\nCB-1,Valve,3\\n", encoding="utf-8")
    assert convert_csv_to_json(src, dst) == [{"sku": "CB-1", "name": "Valve", "qty": "3"}]
'''
    (proj / "csv_to_json.py").write_text(converter_code, encoding="utf-8")
    (proj / "test_csv_to_json.py").write_text(test_code, encoding="utf-8")
    reply = f"CB-09 project created at {proj}"
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
        "step_update": {"step_type": "agent_response", "text_delta": reply},
    }), flush=True)
    print(json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS", "conversation_id": cid, "response": reply},
    }), flush=True)
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": reply}))
""".replace("__CONV_ID__", _CONV_ID)

_MOCK_REPAIRER_AGY_BODY = """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("mock-repairer-model  Mock Repairer")
    sys.exit(0)

prompt = " ".join(args)
cwd = Path.cwd()
replacements = {
    "mod_a.py": "def fn_a() -> str:\\n    return 'ok_a'\\n",
    "mod_b.py": "def fn_b() -> str:\\n    return 'ok_b'\\n",
}
patched = []
for fname, content in replacements.items():
    target = cwd / fname
    if target.is_file() and (
        fname in prompt
        or fname.replace(".py", "") in prompt
        or (fname == "mod_a.py" and "test_a" in prompt)
        or (fname == "mod_b.py" and "test_b" in prompt)
    ):
        target.write_text(content, encoding="utf-8")
        patched.append(fname)

reply = json.dumps({"patched_files": patched, "status": "ok"})
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({"event": "init", "conversation_id": "t3-repair-cid"}), flush=True)
    print(
        json.dumps(
            {
                "event": "result",
                "result": {
                    "status": "SUCCESS",
                    "conversation_id": "t3-repair-cid",
                    "response": reply,
                },
            }
        ),
        flush=True,
    )
else:
    print(
        json.dumps(
            {
                "status": "SUCCESS",
                "conversation_id": "t3-repair-cid",
                "response": reply,
            }
        )
    )
"""


def _git_head_sha(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_isolated_repo(
    repo_dir: Path,
    *,
    files: dict[str, str] | None = None,
    with_qa_branch: bool = False,
) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-e2e@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA E2E"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    seed_files = files or {
        "app_mod.py": "def ok() -> bool:\n    return False\n",
        "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
    }
    for rel_path, content in seed_files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial isolated repo"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    if with_qa_branch:
        subprocess.run(
            ["git", "branch", "qa/autopilot"],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )
    return _git_head_sha(repo_dir)


def _create_candidate_branch(
    repo_dir: Path,
    branch_name: str,
    *,
    files: dict[str, str],
    base_ref: str = "main",
) -> str:
    subprocess.run(
        ["git", "checkout", "-B", branch_name, base_ref],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    for rel_path, content in files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"candidate {branch_name}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


def _seed_jsonl_to_size(path: Path, min_bytes: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    pad = "x" * 900
    lines: list[str] = []
    written = 0
    idx = 0
    while written < min_bytes:
        idx += 1
        line = json.dumps({"id": f"t3_seed_{idx}", "source": "seed", "pad": pad}) + "\n"
        lines.append(line)
        written += len(line.encode("utf-8"))
    path.write_text("".join(lines), encoding="utf-8")
    return path.stat().st_size


def _query_sqlite_tables(camp_dir: Path, table_name: str) -> list[dict[str, Any]]:
    rows_out: list[dict[str, Any]] = []
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if table_name not in tables:
                continue
            for raw_row in conn.execute(f"SELECT * FROM {table_name}").fetchall():
                row_dict = dict(raw_row)
                payload_raw = row_dict.get("payload_json")
                if isinstance(payload_raw, str) and payload_raw.strip():
                    parsed_payload = json.loads(payload_raw)
                    if isinstance(parsed_payload, dict):
                        row_dict = {**row_dict, **parsed_payload}
                for key, val in list(row_dict.items()):
                    if isinstance(val, str) and val.startswith(("[", "{")):
                        with contextlib.suppress(json.JSONDecodeError):
                            row_dict[key] = json.loads(val)
                rows_out.append(row_dict)
    return rows_out


def _load_megaplan_run_records(camp_dir: Path) -> list[dict[str, Any]]:
    records = _query_sqlite_tables(camp_dir, "qa_run_records")
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


def _assert_clean_cli(res: CliResult) -> str:
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert "unrecognized arguments" not in combined, f"CLI rejected args:\n{res.stderr}"
    assert "notimplementederror" not in combined, f"Hit NotImplementedError:\n{res.stderr}"
    assert "validationerror" not in combined, f"Unexpected ValidationError:\n{res.stderr}"
    assert "extra inputs are not permitted" not in combined, (
        f"Unexpected extra_forbidden error:\n{res.stderr}"
    )
    assert "extra_forbidden" not in combined, f"Unexpected extra_forbidden error:\n{res.stderr}"
    assert "traceback (most recent call last)" not in combined, (
        f"Unhandled traceback:\n{res.stdout}\n{res.stderr}"
    )
    for crash_tok in ("keyerror", "attributeerror", "typeerror", "nameerror"):
        assert crash_tok not in combined, (
            f"Unexpected {crash_tok} crash:\n{res.stdout}\n{res.stderr}"
        )
    return combined


def _run_baseline_to_dir(
    qa_cli_runner: QACliRunner,
    qa_env: IsolatedQAEnv,
    camp_dir: Path,
    *,
    lane: str = "local_deterministic",
    log_dir: Path | None = None,
    skip_browser: bool = True,
) -> dict[str, Any]:
    cmd = [
        "baseline",
        "--target-url",
        qa_env.base_url,
        "--output-dir",
        str(camp_dir),
        "--lane",
        lane,
        "--no-build-frontend",
    ]
    if skip_browser:
        cmd.append("--skip-browser")
    if log_dir is not None:
        cmd.extend(["--log-dir", str(log_dir)])
    res = qa_cli_runner.run(cmd)
    _assert_clean_cli(res)
    assert res.returncode == 0, f"baseline failed: {res.stderr}\n{res.stdout}"
    return dict(json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8")))


class _DynamicCatalogState:
    def __init__(self, fixture: ValveCatalogFixture) -> None:
        self.lock = threading.Lock()
        self.fixture = fixture

    def update(self, fixture: ValveCatalogFixture) -> None:
        with self.lock:
            self.fixture = fixture


@contextlib.contextmanager
def _serve_valve_catalog(
    initial: ValveCatalogFixture,
) -> Iterator[tuple[str, _DynamicCatalogState]]:
    state = _DynamicCatalogState(initial)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with state.lock:
                cur = state.fixture
                pages = cur.render_html_pages()
                records = cur.to_json_records()
            if self.path == "/index.json":
                payload = json.dumps(records).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path in pages:
                payload = pages[self.path].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_qa_free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


def _is_loopback_browser_url(url: str) -> bool:
    if url.startswith(("data:", "blob:", "about:")):
        return True
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https", "ws", "wss"}:
        return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS
    return False


@contextlib.asynccontextmanager
async def _vnc_safe_browser_page(
    strict_browser_page: StrictBrowserPage,
) -> AsyncIterator[Page]:
    """Provide a BrowserContext without WebSocketRoute mock so @novnc/novnc attaches cleanly."""
    ctx = await strict_browser_page.browser.new_context(viewport={"width": 1280, "height": 800})

    async def _http_guard(route: Route) -> None:
        req_url = route.request.url
        if _is_loopback_browser_url(req_url):
            await route.continue_()
        else:
            strict_browser_page.external_requests.append(req_url)
            await route.abort()

    await ctx.route("**/*", _http_guard)
    page: Page = await ctx.new_page()

    def _on_console(msg: ConsoleMessage) -> None:
        if msg.type == "error":
            strict_browser_page.console_errors.append(msg.text)

    def _on_pageerror(exc: Exception) -> None:
        strict_browser_page.page_errors.append(repr(exc))

    def _on_response(resp: Response) -> None:
        if resp.status >= 400:
            strict_browser_page.http_errors.append((resp.status, resp.url))

    def _ws_observer(ws: WebSocket) -> None:
        if not _is_loopback_browser_url(ws.url):
            strict_browser_page.external_requests.append(ws.url)

        def _on_ws_socketerror(err_msg: str) -> None:
            strict_browser_page.page_errors.append(f"ws.socketerror({ws.url}): {err_msg}")

        ws.on("socketerror", _on_ws_socketerror)

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)
    page.on("response", _on_response)
    page.on("websocket", _ws_observer)

    try:
        yield page
    finally:
        with contextlib.suppress(Exception):
            await ctx.unroute_all(behavior="ignoreErrors")
        with contextlib.suppress(Exception):
            await page.close()
        with contextlib.suppress(Exception):
            await ctx.close()


class _NoSignalUvicorn(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


class _ControllableLabStack:
    """Loopback synthetic SCADA/Maint/EffectSim stack with mutable ScadaState."""

    def __init__(self, *, scada_fixture_mode: str = "auth_expired") -> None:
        from lab.effect_sim import create_effect_sim_app
        from lab.maintenance_app import create_maintenance_app
        from lab.scada_app import ScadaState, create_scada_app

        self.scada_state = ScadaState(fixture_mode=scada_fixture_mode)
        self._create_scada_app = create_scada_app
        self._create_maintenance_app = create_maintenance_app
        self._create_effect_sim_app = create_effect_sim_app
        self.scada_port: int = 0
        self.maintenance_port: int = 0
        self.effect_sim_port: int = 0
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[_NoSignalUvicorn] = []
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def scada_url(self) -> str:
        return f"http://127.0.0.1:{self.scada_port}"

    @property
    def maintenance_url(self) -> str:
        return f"http://127.0.0.1:{self.maintenance_port}"

    @property
    def effect_sim_url(self) -> str:
        return f"http://127.0.0.1:{self.effect_sim_port}"

    def env_vars(self) -> dict[str, str]:
        return {
            "GROKBOT_SCADA_URL": self.scada_url,
            "GROKBOT_MAINTENANCE_URL": self.maintenance_url,
            "GROKBOT_EFFECT_SIM_URL": self.effect_sim_url,
        }

    def start(self, timeout: float = 10.0) -> _ControllableLabStack:
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(
            target=self._run_thread, daemon=True, name="qa-t3-controllable-lab"
        )
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            self.stop()
            raise TimeoutError("Timed out starting controllable lab stack.")
        if self._error is not None:
            err = self._error
            self.stop()
            raise RuntimeError(f"Controllable lab stack failed: {err!r}") from err
        return self

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve_all())
        except BaseException as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()
        finally:
            loop.close()

    async def _serve_all(self) -> None:
        now_ref = datetime.now(UTC)
        self.scada_state.set_reference_time(now_ref)
        scada_app: FastAPI = self._create_scada_app(state=self.scada_state)
        maint_app: FastAPI = self._create_maintenance_app(fixture_mode="default")
        maint_app.state.maintenance_state.set_reference_time(now_ref)
        effect_app: FastAPI = self._create_effect_sim_app()

        sockets: list[socket.socket] = []
        used_ports: set[int] = set()
        tasks: list[asyncio.Task[None]] = []
        try:
            for app in (scada_app, maint_app, effect_app):
                port = alloc_free_port("127.0.0.1", exclude=used_ports | FORBIDDEN_PORTS)
                used_ports.add(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.listen(128)
                sock.setblocking(False)
                sockets.append(sock)
                srv = _NoSignalUvicorn(
                    uvicorn.Config(
                        app,
                        host="127.0.0.1",
                        port=port,
                        log_level="warning",
                        access_log=False,
                        lifespan="on",
                    )
                )
                self._servers.append(srv)
                tasks.append(asyncio.create_task(srv.serve(sockets=[sock])))

            for srv, task in zip(self._servers, tasks, strict=True):
                deadline = asyncio.get_running_loop().time() + 10.0
                while not srv.started:
                    if task.done():
                        raise RuntimeError(f"Lab server exited early: {task.exception()!r}")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("Timed out waiting for lab uvicorn server.")
                    await asyncio.sleep(0.01)

            self.scada_port = int(sockets[0].getsockname()[1])
            self.maintenance_port = int(sockets[1].getsockname()[1])
            self.effect_sim_port = int(sockets[2].getsockname()[1])
            self._ready.set()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for srv in reversed(self._servers):
                srv.should_exit = True
            for task in tasks:
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            for sock in sockets:
                with contextlib.suppress(OSError):
                    sock.close()

    def stop(self) -> None:
        loop = self._loop
        if loop is not None and not loop.is_closed():
            for srv in reversed(self._servers):
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(setattr, srv, "should_exit", True)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._thread = None
        self._servers.clear()


@contextlib.contextmanager
def _mock_repairer_env(fake_home: Path | None) -> Iterator[dict[str, str]]:
    assert fake_home is not None
    bin_dir = fake_home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    agy_path = bin_dir / "agy"
    agy_path.write_text(_MOCK_REPAIRER_AGY_BODY, encoding="utf-8")
    os.chmod(agy_path, 0o755)

    port = alloc_qa_free_port()

    class _MockLlmHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps({"data": [{"id": "mock-repairer-model"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            patch_map = {
                "mod_a": ("mod_a.py", "def fn_a() -> str:\n    return 'ok_a'\n"),
                "mod_b": ("mod_b.py", "def fn_b() -> str:\n    return 'ok_b'\n"),
            }
            files_out: dict[str, str] = {}
            for key, (fname, content) in patch_map.items():
                if key in raw_body or fname in raw_body:
                    files_out[fname] = content
            resp_obj = {
                "id": "chatcmpl-mock-t3",
                "object": "chat.completion",
                "model": "mock-repairer-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"files": files_out}),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            payload = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _MockLlmHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "GROKBOT_LLM_BASE_URL": f"http://127.0.0.1:{port}",
            "GROKBOT_LLM_API_KEY": "mock-t3-api-key",
            "GROKBOT_LLM_MODEL_ID": "mock-repairer-model",
        }
    finally:
        httpd.shutdown()
        httpd.server_close()
        with contextlib.suppress(OSError):
            agy_path.unlink()


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
        if snap["run"]["status"] in {
            "succeeded",
            "partial",
            "failed",
            "cancelled",
            "waiting_for_input",
        }:
            return snap
        await asyncio.sleep(0.15)
    raise TimeoutError(f"Task {run_id} did not settle within {timeout}s")


def _parse_event_cursor(event_id: str | None) -> tuple[str | None, int | None]:
    if not event_id:
        return None, None
    if event_id.startswith("evt_"):
        parts = event_id.split("_", 2)
        if len(parts) == 3 and parts[1].isdigit():
            return parts[2], int(parts[1])
    if ":" in event_id:
        epoch, seq_raw = event_id.split(":", 1)
        if seq_raw.isdigit():
            return epoch, int(seq_raw)
    return None, None


# ---------------------------------------------------------------------------
# Axis 1: Campaign CLI x Isolation
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t3_cli_baseline_scan_report_with_isolated_lab_never_touches_live(
    qa_lab_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 1: baseline->scan->report works against qa_lab_env while refusing live :8000/DB."""
    live_dbs = sorted((_REPO_ROOT / "var").glob("controlbot*.sqlite3*"))
    before_stats = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()}

    canary_qs = "CANARY_T3_AXIS1_TOK_111"
    with qa_lab_env.client() as client:
        miss = client.get(f"/api/v1/threads/t3_axis1_missing/messages?token={canary_qs}")
        assert miss.status_code == 404
        miss_req_id = miss.headers.get("X-Request-Id", "")
        assert miss_req_id.startswith("req_")

    camp_dir = tmp_path / "camp_axis1"
    _run_baseline_to_dir(
        qa_cli_runner, qa_lab_env, camp_dir, log_dir=qa_lab_env.logs_dir, skip_browser=True
    )

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--ingest-logs",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"
    records = _load_megaplan_run_records(camp_dir)
    cb00 = [r for r in records if r.get("case_id") == "CB-00"]
    assert cb00 and cb00[-1]["passed"] is True

    rep_res = qa_cli_runner.run(["report", "--campaign-dir", str(camp_dir), "--json"])
    _assert_clean_cli(rep_res)
    assert rep_res.returncode == 0, f"report failed: {rep_res.stderr}\n{rep_res.stdout}"
    rep_json = rep_res.json_stdout()
    assert rep_json["ok"] is True
    stats = rep_json["stats"]
    assert stats["open_p0"] == 0
    assert stats["open_p1"] == 0
    assert "median_ms" in stats and "p95_ms" in stats

    handoff_text = (camp_dir / "HANDOFF.md").read_text(encoding="utf-8")
    daily_text = (camp_dir / "daily_report.md").read_text(encoding="utf-8")
    assert handoff_text.strip() and daily_text.strip()
    for artifact in (rep_json, handoff_text, daily_text, records):
        assert_no_secret_leak(artifact, secrets=(canary_qs, qa_lab_env.cap_secret))

    # Refusal of live :8000 and live DB path pre-network
    base_sha = _init_isolated_repo(tmp_path / "axis1_guard_repo")
    bad_8000_dir = tmp_path / "camp_bad_8000"
    bad_8000_dir.mkdir(parents=True, exist_ok=True)
    (bad_8000_dir / "campaign.json").write_text(
        json.dumps(
            {
                "campaign_id": "t3-refuse-8000",
                "base_sha": base_sha,
                "lane": "local_deterministic",
                "target_url": "http://127.0.0.1:8000",
                "status": "active",
                "output_dir": str(bad_8000_dir),
            }
        ),
        encoding="utf-8",
    )
    res_8000 = qa_cli_runner.run(["scan", "--campaign-dir", str(bad_8000_dir), "--cases", "CB-00"])
    combined_8000 = _assert_clean_cli(res_8000)
    assert res_8000.returncode != 0
    assert any(tok in combined_8000 for tok in ("forbidden", "live", "isolation", "port"))

    res_live_db = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"],
        env_overrides={"GROKBOT_DB_PATH": str(_REPO_ROOT / "var" / "controlbot.sqlite3")},
    )
    combined_db = _assert_clean_cli(res_live_db)
    assert res_live_db.returncode != 0
    assert any(
        tok in combined_db
        for tok in ("isolation", "forbidden", "live", "controlbot.sqlite3", "boundary")
    )

    after_stats = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()}
    assert after_stats == before_stats


@pytest.mark.qa_megaplan
def test_t3_cli_repair_accept_rollback_lifecycle_enforces_policy_guard_on_isolated_git(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 1: accept rejects PolicyGuard violations, promotes clean fix, and rollback restores."""
    repo_dir = tmp_path / "axis1_git_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "src/factory/policy.py": "# protected placeholder\n",
            "tests/e2e/test_locked.py": "def test_locked() -> None:\n    assert True\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro_app.py": (
                "from app_mod import ok\ndef test_repro() -> None:\n    assert ok()\n"
            ),
        },
        with_qa_branch=True,
    )
    bad_pol_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-pol-bad",
        files={"src/factory/policy.py": "# tampered!\n"},
        base_ref=base_sha,
    )
    bad_e2e_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-e2e-bad",
        files={"tests/e2e/test_locked.py": "def test_locked() -> None:\n    assert False\n"},
        base_ref=base_sha,
    )
    clean_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-clean-ok",
        files={"app_mod.py": "def ok() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_axis1_lifecycle"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    repro_cmd = f"{sys.executable} -m pytest -q test_repro_app.py"
    for cid, csha, branch, fmod in (
        ("cand-pol-bad", bad_pol_sha, "qa/cand-pol-bad", ["src/factory/policy.py"]),
        ("cand-e2e-bad", bad_e2e_sha, "qa/cand-e2e-bad", ["tests/e2e/test_locked.py"]),
        ("cand-clean-ok", clean_sha, "qa/cand-clean-ok", ["app_mod.py"]),
    ):
        (camp_dir / "candidates" / f"{cid}.json").write_text(
            json.dumps(
                {
                    "candidate_id": cid,
                    "item_id": f"item-{cid}",
                    "campaign_id": state["campaign_id"],
                    "base_sha": base_sha,
                    "candidate_sha": csha,
                    "branch_name": branch,
                    "files_modified": fmod,
                    "repro_test_path": "test_repro_app.py",
                    "rerun_command": repro_cmd,
                    "baseline_passed": False,
                    "candidate_passed": True,
                    "audit_passed": True,
                    "author_model": "hydrogen",
                    "auditor_model": "pro",
                    "status": "candidate_verified",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    for bad_cid in ("cand-pol-bad", "cand-e2e-bad"):
        bad_res = qa_cli_runner.run(
            [
                "accept",
                "--campaign-dir",
                str(camp_dir),
                "--candidate",
                bad_cid,
                "--no-build-frontend",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        bad_comb = _assert_clean_cli(bad_res)
        assert bad_res.returncode != 0
        assert any(
            tok in bad_comb for tok in ("policy", "immutable", "violation", "protected", "audit")
        )
        assert _git_head_sha(repo_dir) == base_sha

    ok_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-clean-ok",
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
            "--json",
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(ok_res)
    assert ok_res.returncode == 0, f"clean accept failed: {ok_res.stderr}\n{ok_res.stdout}"
    assert _git_head_sha(repo_dir) == clean_sha
    assert json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))[
        "last_accepted_sha"
    ] == clean_sha

    rb_res = qa_cli_runner.run(
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-clean-ok",
            "--repo-root",
            str(repo_dir),
            "--json",
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(rb_res)
    assert rb_res.returncode == 0, f"rollback failed: {rb_res.stderr}\n{rb_res.stdout}"
    assert _git_head_sha(repo_dir) == base_sha
    assert json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))[
        "last_accepted_sha"
    ] == base_sha
    rb_manifest_path = camp_dir / "rollbacks" / "qa_rollback_cand-clean-ok.json"
    assert rb_manifest_path.is_file()
    rb_manifest = json.loads(rb_manifest_path.read_text(encoding="utf-8"))
    assert rb_manifest["previous_accepted_sha"] == base_sha


@pytest.mark.qa_existing
def test_t3_isolated_qa_env_with_lab_stack_and_factory_engine_isolation(
    qa_lab_env: IsolatedQAEnv,
    tmp_path: Path,
) -> None:
    """Axis 1: qa_lab_env ports disjoint from live; FactoryStore/PolicyGuard isolate cleanly."""
    qa_lab_env.assert_isolated_from_live()
    assert qa_lab_env.lab_stack is not None
    lab_ports = {
        qa_lab_env.port,
        qa_lab_env.vnc_port,
        qa_lab_env.lab_stack.scada_port,
        qa_lab_env.lab_stack.maintenance_port,
        qa_lab_env.lab_stack.effect_sim_port,
    }
    assert lab_ports.isdisjoint(FORBIDDEN_PORTS)
    assert len(lab_ports) == 5

    live_db = _REPO_ROOT / "var" / "controlbot.sqlite3"
    with pytest.raises(IsolationBoundaryError):
        FactoryStore(live_db, forbidden_db_paths=(live_db,))
    with pytest.raises(IsolationBoundaryError):
        FactoryStore(qa_lab_env.db_path, forbidden_db_paths=(qa_lab_env.db_path,))

    repo_dir = tmp_path / "iso_factory_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "src/factory/policy.py": "# protected\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
        },
    )
    store = FactoryStore(tmp_path / "iso_factory.sqlite3", forbidden_db_paths=(live_db,))
    IsolationGuard.validate_paths(store.db_path, repo_dir, forbidden_db_paths=(live_db,))
    guard = PolicyGuard()
    engine = FactoryEngine(
        repo_dir,
        store,
        policy_guard=guard,
        budget=CycleBudget(budget_id="t3-iso", max_cycles=2, max_attempts=2),
        owner="t3-worker",
        base_branch="main",
        artifacts_dir=tmp_path / "iso_artifacts",
    )
    store.add_backlog_item(
        BacklogItem(
            item_id="item-t3-iso",
            title="Fix app_mod.ok",
            priority=1,
            hypothesis="Return True in app_mod.ok",
            target_metric="failures",
            baseline_repro_cmd="pytest -q",
        )
    )

    bad_files = {"src/factory/policy.py": "# tampered\n"}
    bad_patch = CandidatePatch(
        candidate_id="cand-t3-pol-bad",
        item_id="item-t3-iso",
        branch_name="qa/cand-t3-pol-bad",
        hypothesis="Forbidden edit",
        target_metric="failures",
        proposal_hash=compute_proposal_hash(
            item_id="item-t3-iso", target_metric="failures", files_to_modify=bad_files
        ),
        files_to_modify=bad_files,
    )
    with pytest.raises(PolicyImmutabilityError):
        engine.run_candidate_cycle(bad_patch)
    assert _git_head_sha(repo_dir) == base_sha

    good_files = {"app_mod.py": "def ok() -> bool:\n    return True\n"}
    good_patch = CandidatePatch(
        candidate_id="cand-t3-good",
        item_id="item-t3-iso",
        branch_name="qa/cand-t3-good",
        hypothesis="Fix return value",
        target_metric="failures",
        proposal_hash=compute_proposal_hash(
            item_id="item-t3-iso", target_metric="failures", files_to_modify=good_files
        ),
        files_to_modify=good_files,
    )

    def _eval_ok(path: Path) -> EvalResult:
        proc = subprocess.run(
            [sys.executable, "-B", "-c", "from app_mod import ok; assert ok()"],
            cwd=str(path),
            capture_output=True,
            text=True,
            check=False,
        )
        return EvalResult(passed=proc.returncode == 0, metric=0.0 if proc.returncode == 0 else 1.0)

    res = engine.run_candidate_cycle(good_patch, evaluator=_eval_ok)
    assert res.candidate_commit is not None and res.candidate_commit != base_sha
    assert res.manifest_path is not None
    assert _git_head_sha(repo_dir) == res.candidate_commit
    rb = rollback_from_manifest(Path(res.manifest_path), repo_path=repo_dir, store=store)
    assert rb["ok"] is True
    assert _git_head_sha(repo_dir) == base_sha


# ---------------------------------------------------------------------------
# Axis 2: React /app Surface x DiagnosticsMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_react_app_surface_diagnostics_correlation_and_dot1_rotation_redaction(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Axis 2: React /app + X-Request-Id + client-error + 10 MiB .1 rotation + secret redaction."""
    failures_path = qa_env.logs_dir / "failures.jsonl"
    rotated_path = qa_env.logs_dir / "failures.jsonl.1"
    seeded_size = _seed_jsonl_to_size(failures_path, _TEN_MIB)
    assert seeded_size >= _TEN_MIB
    assert not rotated_path.exists()
    old_stat = failures_path.stat()
    old_identity = (old_stat.st_dev, old_stat.st_ino)

    await assert_react_app_surface(qa_env.base_url, strict_browser_page)

    canaries = (
        "CANARY_T3_FE_BEARER_201",
        "CANARY_T3_FE_QS_202",
        "CANARY_T3_FE_CRED_203",
        "CANARY_T3_BE_COOKIE_204",
        "CANARY_T3_BE_TOKEN_205",
    )
    c_fe_bearer, c_fe_qs, c_fe_cred, c_be_cookie, c_be_tok = canaries

    beacon: dict[str, Any] = await strict_browser_page.page.evaluate(
        """async ([bearer, qs, cred]) => {
            const infoRes = await fetch('/api/system/info');
            const reqId = infoRes.headers.get('x-request-id') || '';
            const postRes = await fetch('/api/v1/diagnostics/client-error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    kind: 't3_rot_probe',
                    message: `Bearer ${bearer} leaked?`,
                    url: `/app?token=${qs}`,
                    page_url: `/app?cap_token=${qs}`,
                    request_id: reqId,
                    extra: {credential: cred}
                })
            });
            return {reqId, status: postRes.status, body: await postRes.json()};
        }""",
        [c_fe_bearer, c_fe_qs, c_fe_cred],
    )
    assert beacon["status"] == 202
    fe_req_id = str(beacon["reqId"])
    assert fe_req_id.startswith("req_")
    strict_browser_page.assert_clean()

    with qa_env.client() as client:
        miss = client.get(
            f"/api/v1/threads/t3_rot_missing/messages?token={c_be_tok}",
            headers={
                "Authorization": f"Bearer {c_fe_bearer}",
                "Cookie": f"sid={c_be_cookie}",
            },
        )
        assert miss.status_code == 404
        be_req_id = miss.headers.get("X-Request-Id", "")
        assert be_req_id.startswith("req_")

        fe_corr = client.get(f"/api/v1/diagnostics/failures?request_id={fe_req_id}").json()
        be_corr = client.get(f"/api/v1/diagnostics/failures?request_id={be_req_id}").json()
        assert any(it.get("request_id") == fe_req_id for it in fe_corr["failures"])
        assert any(it.get("request_id") == be_req_id for it in be_corr["failures"])
        assert_no_secret_leak(fe_corr, secrets=(*canaries, qa_env.cap_secret))
        assert_no_secret_leak(be_corr, secrets=(*canaries, qa_env.cap_secret))

    assert rotated_path.is_file()
    rot_stat = rotated_path.stat()
    assert (rot_stat.st_dev, rot_stat.st_ino) == old_identity

    new_stat = failures_path.stat()
    assert (new_stat.st_dev, new_stat.st_ino) != old_identity
    assert new_stat.st_size < _TEN_MIB
    active_rows = [
        json.loads(line)
        for line in failures_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    active_req_ids = {str(r.get("request_id", "")) for r in active_rows}
    assert fe_req_id in active_req_ids
    assert be_req_id in active_req_ids
    assert_no_secret_leak(active_rows, secrets=(*canaries, qa_env.cap_secret))


@pytest.mark.qa_existing
async def test_t3_auth_react_app_token_propagation_vault_4xx_and_diagnostics_omission(
    qa_auth_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Axis 2: Auth React /app token propagation + unauth 401 + vault body omission."""
    token = qa_auth_env.web_token
    assert token is not None

    surface = await assert_react_app_surface(
        qa_auth_env.base_url, strict_browser_page, web_token=token
    )
    assert str(surface["request_id"]).startswith("req_")

    with httpx.Client(base_url=qa_auth_env.base_url, timeout=10.0) as anon:
        unauth = anon.get("/api/v1/bots")
        assert unauth.status_code == 401
        unauth_req_id = unauth.headers.get("X-Request-Id", "")
        assert unauth_req_id.startswith("req_")

    vault_secret = "CANARY_T3_VAULT_SECRET_301"
    with qa_auth_env.client() as client:
        vault_resp = client.post("/api/v1/vault/secure-fill", json={"secret_value": vault_secret})
        assert vault_resp.status_code >= 400
        vault_req_id = vault_resp.headers.get("X-Request-Id", "")
        assert vault_req_id.startswith("req_")

        vault_diag = client.get(f"/api/v1/diagnostics/failures?request_id={vault_req_id}").json()
        assert vault_diag["failures"]
        assert vault_diag["failures"][0]["detail"]["response_preview"] == (
            "[vault response body omitted]"
        )

        for ep in (
            "/api/v1/diagnostics/summary",
            "/api/v1/diagnostics/failures?limit=100",
            "/api/v1/diagnostics/requests?limit=100",
        ):
            payload = client.get(ep).json()
            assert_no_secret_leak(payload, secrets=(token, qa_auth_env.cap_secret, vault_secret))

    for fname in ("failures.jsonl", "requests.jsonl"):
        fpath = qa_auth_env.logs_dir / fname
        assert fpath.is_file()
        raw = fpath.read_text(encoding="utf-8")
        assert token not in raw
        assert vault_secret not in raw
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        assert_no_secret_leak(rows, secrets=(token, qa_auth_env.cap_secret, vault_secret))

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Axis 3: UI Control Discovery x UX Metrics
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t3_ui_discovery_coverage_and_ux_png_checkpoints_on_live_react_app(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 3: scan --discover-controls emits consistent coverage.json & valid PNG checkpoints."""
    camp_dir = tmp_path / "camp_axis3_disc"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=False)

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--discover-controls",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    cov_path = camp_dir / "coverage.json"
    assert cov_path.is_file()
    cov = json.loads(cov_path.read_text(encoding="utf-8"))
    assert cov["total_controls"] > 0
    assert cov["covered_count"] > 0
    assert (
        cov["covered_count"]
        + cov["blocked_count"]
        + cov["pending_count"]
        + cov["out_of_scope_count"]
        == cov["total_controls"]
    )
    by_mod = cov["by_module"]
    assert isinstance(by_mod, dict) and by_mod
    for item in cov["items"]:
        if item["coverage_status"] != "covered":
            assert str(item.get("blocked_reason") or "").strip()
    assert_no_secret_leak(cov, secrets=(qa_env.cap_secret,))

    pngs = sorted(camp_dir.glob("**/*.png"))
    assert pngs, f"Expected PNG checkpoints under {camp_dir}"
    for png in pngs:
        raw = png.read_bytes()
        assert raw[:8] == _PNG_MAGIC
        assert len(raw) > 512


@pytest.mark.qa_existing
async def test_t3_react_modal_focus_escape_disabled_states_and_ttfp_error_png(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Axis 3: Disabled controls, modal focus/Escape, TTFP+Stop & Memory 409 alert PNG."""
    env = qa_env_factory(mock_agy_script=_T3_CORE_MOCK_AGY_SCRIPT, name="t3_ux_focus")
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.wait_for(state="visible", timeout=15000)

    # Disabled controls check
    assert await page.locator('button[aria-label="Send message"]').is_disabled()
    dialog = page.locator('[role="dialog"][aria-modal="true"]')

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    await dialog.wait_for(state="visible")
    assert await dialog.get_by_role("button", name="Create bot").is_disabled()
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    await dialog.wait_for(state="visible")
    assert await dialog.get_by_role("button", name="Create group chat").is_disabled()
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")

    # Focus trap & Escape focus restore on Settings & Keyboard shortcuts
    for aria_label in ("Settings", "Keyboard shortcuts"):
        btn = page.locator(f'aside button[aria-label="{aria_label}"]')
        await btn.focus()
        await btn.click()
        await dialog.wait_for(state="visible")
        await page.wait_for_function(
            """() => {
                const d = document.querySelector('[role="dialog"][aria-modal="true"]');
                return Boolean(d && d.contains(document.activeElement));
            }"""
        )
        await page.keyboard.press("Escape")
        await dialog.wait_for(state="hidden")
        await page.wait_for_function(
            f"""() => {{
                const b = document.querySelector('aside button[aria-label="{aria_label}"]');
                return Boolean(b && document.activeElement === b);
            }}"""
        )

    # TTFP & Stop affordance on delayed generation
    stop_seen = False

    async def _send_ux() -> bool:
        await composer.fill("UX_DELAY_PROBE measure latency")
        await composer.press("Enter")
        await page.get_by_text("Tier 3 UX delayed response ready.").wait_for(
            state="visible", timeout=15000
        )
        return True

    async def _probe_ux() -> bool:
        nonlocal stop_seen
        stop_vis = await page.locator('button[aria-label="Stop current generation"]').is_visible()
        if stop_vis:
            stop_seen = True
        work_vis = await page.get_by_text("Working…").is_visible()
        return stop_vis or work_vis

    done, timing = await measure_ttfp_and_completion(
        _send_ux,
        actions_to_reach=2,
        ttfp_probe=_probe_ux,
        cancel_available=True,
        poll_interval_s=0.02,
    )
    assert done is True
    assert isinstance(timing, UxTimingResult)
    assert timing.ttfp_ms is not None and 0.0 <= timing.ttfp_ms < timing.completion_ms
    assert stop_seen is True

    # Memory 409 conflict [role="alert"] + PNG error checkpoint
    await page.locator("aside").get_by_role("button", name=re.compile(r"Memory", re.I)).click()
    await dialog.wait_for(state="visible")
    await dialog.get_by_role("button", name="New memory").click()
    await dialog.get_by_label("Title").fill("T3 Race Memory")
    await dialog.get_by_label("Content").fill("v1")
    await dialog.get_by_role("button", name="Save memory").click()
    await dialog.get_by_text("T3 Race Memory").wait_for(state="visible")
    await dialog.get_by_role("button", name="Edit T3 Race Memory").click()

    with env.client() as client:
        items = client.get("/api/v1/memory").json()["items"]
        target = next(it for it in items if it["title"] == "T3 Race Memory")
        assert (
            client.patch(
                f"/api/v1/memory/{target['id']}",
                json={"revision": target["revision"], "content": "v2 server"},
            ).status_code
            == 200
        )

    await dialog.get_by_label("Content").fill("v2 stale ui")
    await dialog.get_by_role("button", name="Save changes").click()
    await dialog.locator('[role="alert"]').get_by_text(
        re.compile(r"409|conflict|revision", re.I)
    ).wait_for(state="visible")

    err_png = tmp_path / "t3_memory_409_alert.png"
    await page.screenshot(path=str(err_png), full_page=True)
    raw_png = err_png.read_bytes()
    assert raw_png[:8] == _PNG_MAGIC and len(raw_png) > 1024

    strict_browser_page.assert_clean(
        allow_http_statuses=[409],
        allow_console_substrings=["409 (Conflict)"],
    )


# ---------------------------------------------------------------------------
# Axis 4: CB-01..CB-03 (Dynamic CB-VALVE-104 + Cancel + SSE Last-Event-ID)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb01_cb02_cb03_dynamic_valve_cancel_and_sse_reconnect_dedup(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Axis 4: Dynamic CB-VALVE-104 query -> price update -> cancel 0-side-effect -> SSE replay."""
    fixture = build_cb_valve_104_catalog()
    assert fixture.active_record.price != fixture.prior_record.price

    with _serve_valve_catalog(fixture) as (catalog_origin, state):
        catalog_port = urlparse(catalog_origin).port
        assert catalog_port is not None
        env = qa_env_factory(mock_agy_script=_T3_CORE_MOCK_AGY_SCRIPT, name="t3_cb01_03")
        with env.client() as client:
            assert (
                client.patch("/api/v1/apps/app_runtime", json={"enabled": False}).status_code
                == 200
            )

        page = strict_browser_page.page
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        composer = page.locator('textarea[aria-label="Message composer"]')

        # 1. Query initial dynamic price
        await composer.fill(f"{fixture.prompt_es} CATALOG_PORT={catalog_port} SKU={fixture.sku}")
        await composer.press("Enter")
        cur_price_str = str(fixture.active_record.price)
        prior_price_str = str(fixture.prior_record.price)
        await page.get_by_text(
            f"{fixture.sku}: {fixture.active_record.currency} {cur_price_str}"
        ).wait_for(state="visible", timeout=15000)

        # 2. Update price dynamically, then exercise CB-03 cancel with 0 post-cancel side effect
        new_price = (fixture.active_record.price + Decimal("14.65")).quantize(Decimal("0.01"))
        updated_fixture = fixture.apply_price_update(new_price, effective_date="2026-11-29")
        state.update(updated_fixture)

        marker_path = env.projects_root / "Grokbotclon" / "t3_cancel_marker.txt"
        assert not marker_path.exists()
        await composer.fill(f"CANCEL_SLEEP_PROBE MARKER={marker_path}")
        await composer.press("Enter")
        stop_btn = page.locator('button[aria-label="Stop current generation"]')
        await stop_btn.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Running slow T3 task...").wait_for(
            state="visible", timeout=10000
        )
        await stop_btn.click()
        await page.locator('button[aria-label="Send message"]').wait_for(
            state="visible", timeout=10000
        )
        await asyncio.sleep(4.0)
        assert not marker_path.exists()

        # 3. Query updated dynamic price
        await composer.fill(
            f"Check updated {updated_fixture.sku} CATALOG_PORT={catalog_port} "
            f"SKU={updated_fixture.sku}"
        )
        await composer.press("Enter")
        upd_price_str = str(updated_fixture.active_record.price)
        await page.get_by_text(
            f"{updated_fixture.sku}: {updated_fixture.active_record.currency} {upd_price_str}"
        ).wait_for(state="visible", timeout=15000)

        with env.client() as client:
            msgs = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            bot_msgs = [m for m in msgs if m["sender_type"] == "bot"]
            assert len(bot_msgs) >= 3
            assert prior_price_str not in str(bot_msgs[0]["content"])
            assert fixture.active_record.source_url in str(bot_msgs[0]["content"])
            assert bot_msgs[1]["status"] == "interrupted"
            assert upd_price_str in str(bot_msgs[-1]["content"])
            assert cur_price_str not in str(bot_msgs[-1]["content"])
            msg_id = str(msgs[0]["id"])

        # 4. SSE Last-Event-ID replay (evt_ and epoch:seq) + browser reload zero duplicate bubbles
        async with env.async_client() as aclient:
            frames: list[SseFrame] = []
            connected = asyncio.Event()

            async def _listen_rx() -> None:
                async for frame in iter_sse_events(aclient, timeout=10.0, on_connected=connected):
                    if frame.event_type == "message.reaction":
                        frames.append(frame)
                        if len(frames) >= 2:
                            return

            task = asyncio.create_task(_listen_rx())
            try:
                await asyncio.wait_for(connected.wait(), timeout=5.0)
                for emoji in ("👍", "🔥"):
                    assert (
                        await aclient.post(
                            f"/api/v1/messages/{msg_id}/reactions",
                            json={"emoji": emoji, "action": "add"},
                        )
                    ).status_code == 200
                await asyncio.wait_for(task, timeout=10.0)
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            anchor_id = str(frames[0].id)
            epoch, seq = _parse_event_cursor(anchor_id)
            assert epoch is not None and seq is not None
            assert (
                await aclient.post(
                    f"/api/v1/messages/{msg_id}/reactions",
                    json={"emoji": "✅", "action": "add"},
                )
            ).status_code == 200

            for headers, query in (
                ({"Last-Event-ID": anchor_id}, ""),
                (None, f"?last_event_id={epoch}:{seq}"),
            ):
                replayed: list[SseFrame] = []
                async for frame in iter_sse_events(
                    aclient,
                    url=f"/api/v1/events/stream{query}",
                    headers=headers,
                    timeout=3.0,
                ):
                    replayed.append(frame)
                    if (
                        frame.event_type == "message.reaction"
                        and isinstance(frame.data, dict)
                        and frame.data.get("payload", {}).get("emoji") == "✅"
                    ):
                        break
                assert all(f.event_type != "stream.resync" for f in replayed)
                emojis = [
                    f.data.get("payload", {}).get("emoji")
                    for f in replayed
                    if f.event_type == "message.reaction" and isinstance(f.data, dict)
                ]
                assert emojis == ["🔥", "✅"]

        await page.reload(wait_until="networkidle")
        expected_upd_msg = (
            f"{updated_fixture.sku}: {updated_fixture.active_record.currency} {upd_price_str}"
        )
        await page.get_by_text(expected_upd_msg).wait_for(state="visible")
        assert await page.get_by_text(expected_upd_msg).count() == 1
        strict_browser_page.assert_clean()


@pytest.mark.qa_megaplan
def test_t3_megaplan_scan_cb01_cb02_cb03_with_dynamic_valve_fixture_and_ref_override(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 4: scan --cases CB-01,CB-02,CB-03 passes with dynamic CB-VALVE-104 fixture."""
    catalog = build_cb_valve_104_catalog()
    camp_dir = tmp_path / "camp_axis4"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)

    (camp_dir / "fixtures").mkdir(parents=True, exist_ok=True)
    (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(
            {
                "fixture_version": catalog.fixture_version,
                "sku": catalog.sku,
                "active_price": str(catalog.active_record.price),
                "prior_price": str(catalog.prior_record.price),
                "currency": catalog.active_record.currency,
                "source_url": catalog.active_record.source_url,
                "records": catalog.to_json_records(),
            },
            indent=2,
        ),
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
                "discoverability": "Single prompt",
                "state_transition": "Returns answer",
                "independent_verification": f"Stale ref claimed {catalog.prior_record.price}",
                "missing_data_or_permission": "None",
                "efficiency_notes": "1 turn",
                "expected_controlbot_contract": (
                    f"Must match {catalog.active_record.currency} {catalog.active_record.price}"
                ),
                "conditions": {
                    "timing_comparability": "observational_only_different_hardware",
                    "privacy_scope": "main_and_test_only_no_tokens_or_cookies",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-01,CB-02,CB-03",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-01", "CB-02", "CB-03"):
        assert case_id in by_case, f"Missing {case_id} in {by_case.keys()}"
        assert by_case[case_id]["passed"] is True, f"{case_id} failed: {by_case[case_id]!r}"
    assert by_case["CB-02"].get("fixture_version") == catalog.fixture_version


# ---------------------------------------------------------------------------
# Axis 5: CB-04 (Roster/Group @mention) x CB-05 (Files/Library/Pages)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb04_group_mention_with_cb05_pages_attachments_thread_isolation(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Axis 5: CB-04 bot/group @mention routing paired with CB-05 Page/attachment isolation."""
    env = qa_env_factory(mock_agy_script=_T3_CORE_MOCK_AGY_SCRIPT, name="t3_cb04_05")
    with env.client() as client:
        att_payload = b"Chief-only valve spec v1\n"
        up = client.post(
            "/api/v1/attachments",
            params={"filename": "chief_spec.txt"},
            headers={"Content-Type": "text/plain"},
            content=att_payload,
        )
        assert up.status_code == 201
        att_id = str(up.json()["id"])
        dl = client.get(f"/api/v1/attachments/{att_id}")
        assert dl.status_code == 200 and dl.content == att_payload
        assert dl.headers.get("X-Content-Type-Options") == "nosniff"

        page_resp = client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Chief Private Blueprint T3",
                "content_md": f"Linked attachment {att_id}",
            },
        )
        assert page_resp.status_code == 201
        art_id = str(page_resp.json()["id"])
        assert (
            client.patch(f"/api/v1/pages/{art_id}", json={"pinned": True}).status_code == 200
        )

        ops_lib = client.get("/api/v1/bots/bot_ops/library").json()["items"]
        assert all(it["id"] != art_id for it in ops_lib)
        ops_msgs = client.get("/api/v1/threads/thr_bot_ops/messages").json()["messages"]
        assert art_id not in json.dumps(ops_msgs)

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    # Create a custom bot and a 2-bot group channel via UI, then @mention ControlBot Ops
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    await page.locator("#new-bot-name").fill("T3 Watcher")
    await page.get_by_role("button", name="Create bot").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message T3 Watcher'"
    )

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dlg = page.get_by_role("dialog")
    await dlg.locator("#new-channel-name").fill("T3 Sync")
    await dlg.get_by_role("button", name="Chief of Staff").click()
    await dlg.get_by_role("button", name="ControlBot Ops").click()
    await dlg.get_by_text("2 / 6 selected").wait_for(state="visible")
    await dlg.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #T3 Sync (use @ to mention bots)'"
    )

    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.click()
    await composer.type("@")
    mention_hdr = page.get_by_text("Mention", exact=True)
    await mention_hdr.wait_for(state="visible")
    await mention_hdr.locator("xpath=..").locator("button").filter(
        has_text="ControlBot Ops"
    ).click()
    await page.wait_for_function(
        "() => /^@controlbot[_-]ops\\s/i.test("
        "document.querySelector('textarea[aria-label=\"Message composer\"]')?.value || '')"
    )
    await composer.type("check status")
    await composer.press("Enter")
    await page.get_by_text("Ops bot targeted reply: telemetry nominal.").wait_for(
        state="visible", timeout=15000
    )

    with env.client() as client:
        channels = client.get("/api/v1/bots").json()["channels"]
        ch = next(c for c in channels if c["name"] == "T3 Sync")
        ch_msgs = client.get(f"/api/v1/threads/{ch['thread_id']}/messages").json()["messages"]
        bot_msgs = [m for m in ch_msgs if m["sender_type"] == "bot"]
        assert len(bot_msgs) == 1 and bot_msgs[0]["sender_bot_id"] == "bot_ops"
        assert art_id not in json.dumps(ch_msgs)

    strict_browser_page.assert_clean()


@pytest.mark.qa_megaplan
def test_t3_megaplan_scan_cb04_cb05_and_discovery_controls_pairwise(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 5: scan --cases CB-04,CB-05 --discover-controls verifies modules & passed=True."""
    camp_dir = tmp_path / "camp_axis5"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=False)

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-04,CB-05",
            "--discover-controls",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0

    cov = json.loads((camp_dir / "coverage.json").read_text(encoding="utf-8"))
    assert "roster" in cov["by_module"]
    assert "artifacts" in cov["by_module"]

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-04", "CB-05"):
        assert case_id in by_case
        assert by_case[case_id]["passed"] is True, f"{case_id} failed: {by_case[case_id]!r}"


# ---------------------------------------------------------------------------
# Axis 6: CB-06 (Computer Takeover/Lease 409/PTY) x CB-07 (effect_sim/Approvals 409)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb06_takeover_lease_409_pty_with_cb07_effect_sim_approval_409(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Axis 6: Takeover 409 + Approval Deny (0 effects) + PTY + effect.apply + replay 409."""
    env = qa_env_factory(with_mock_rfb=True, with_lab=True, name="t3_cb06_07")
    assert env.lab_stack is not None
    assert env.mock_rfb is not None

    async with _vnc_safe_browser_page(strict_browser_page) as page:
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        await page.locator('button[title="Open Bot Computer"]').click()
        await page.get_by_role("button", name="Screen", exact=True).click()
        await page.locator("canvas").first.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Starting display").wait_for(state="hidden", timeout=10000)
        assert env.mock_rfb.handshakes_completed >= 1

        await page.get_by_role("button", name="Take control").click()
        dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
        await dlg.wait_for(state="visible")
        await dlg.locator("span").filter(has_text="You're in control").first.wait_for(
            state="visible"
        )

        # Agent computer action blocked with 409; approval Deny keeps effect_sim == 0
        with env.client() as client:
            blocked = client.post(
                "/api/v1/computers/default/actions",
                json={"type": "start", "url": env.url("/health"), "actor": "agent"},
            )
            assert blocked.status_code == 409

            appr = client.post(
                "/api/v1/approvals",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "title": "Reset standby valve",
                    "allow_always_allowed": False,
                },
            )
            assert appr.status_code == 201
            appr_id = str(appr.json()["id"])
            assert (
                client.post(
                    f"/api/v1/approvals/{appr_id}/resolve",
                    json={"decision": "deny"},
                ).status_code
                == 200
            )
            eff_before = client.get(f"{env.lab_stack.effect_sim_url}/api/effects/state").json()
            assert eff_before["total_applied"] == 0

        await dlg.get_by_role("button", name="I'm done").click()
        await dlg.wait_for(state="hidden")
        await page.get_by_text("Control returned to your Bot").wait_for(state="visible")

        # PTY execution in Terminal tab
        await page.get_by_role("button", name="Terminal", exact=True).click()
        await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
        await page.locator(".xterm-helper-textarea").focus()
        await page.keyboard.type("echo QA_T3_PTY_OK")
        await page.keyboard.press("Enter")
        await page.wait_for_function(
            "() => (document.querySelector('.xterm-rows')?.innerText || '')"
            ".includes('QA_T3_PTY_OK')",
            timeout=10000,
        )

    strict_browser_page.assert_clean()

    # Handback allows agent actions; effect.apply increments once & conflicts return 409
    async with env.async_client(timeout=35.0) as aclient:
        agent_ok = await aclient.post(
            "/api/v1/computers/default/actions",
            json={"type": "start", "url": env.url("/health"), "actor": "agent"},
        )
        assert agent_ok.status_code == 200
        assert (
            await aclient.post(
                "/api/v1/computers/default/actions",
                json={"type": "stop", "actor": "agent"},
            )
        ).status_code == 200

        task_resp = await aclient.post(
            "/api/tasks",
            json={
                "query": "Apply effect operation_key=t3-op-01 reset_latch on bomba-34-a1",
                "facility_id": "facility-a",
                "allowed_areas": ["area-1"],
                "allowed_tools": ["effect.apply", "effect.inspect_state"],
                "read_only": False,
            },
        )
        assert task_resp.status_code == 201
        snap = await _poll_task_until_terminal(aclient, str(task_resp.json()["run_id"]))
        assert snap["run"]["status"] == "succeeded"

        eff_url = env.lab_stack.effect_sim_url
        eff_state = (await aclient.get(f"{eff_url}/api/effects/state")).json()
        assert eff_state["total_applied"] == 1
        applied_key = str(eff_state["effects"][0]["idempotency_key"])

        conflict_eff = await aclient.post(
            f"{eff_url}/api/effects/apply",
            json={
                "idempotency_key": applied_key,
                "asset_id": "bomba-34-a1",
                "action": "trip_breaker",
                "params": {"mode": "unsafe"},
            },
        )
        assert conflict_eff.status_code == 409
        assert (await aclient.get(f"{eff_url}/api/effects/state")).json()["total_applied"] == 1

        appr2 = await aclient.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Second action",
                "allow_always_allowed": False,
            },
        )
        assert appr2.status_code == 201
        appr2_id = str(appr2.json()["id"])
        assert (
            await aclient.post(
                f"/api/v1/approvals/{appr2_id}/resolve",
                json={"decision": "allow_once"},
            )
        ).status_code == 200
        assert (
            await aclient.post(
                f"/api/v1/approvals/{appr2_id}/resolve",
                json={"decision": "deny"},
            )
        ).status_code == 409


@pytest.mark.qa_megaplan
def test_t3_megaplan_scan_cb06_cb07_with_lab_isolation(
    qa_lab_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 6: scan --cases CB-06,CB-07 runs isolated against qa_lab_env with passed=True."""
    camp_dir = tmp_path / "camp_axis6"
    _run_baseline_to_dir(qa_cli_runner, qa_lab_env, camp_dir, skip_browser=True)

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-06,CB-07", "--json"]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0
    qa_lab_env.assert_isolated_from_live()

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-06", "CB-07"):
        assert case_id in by_case
        assert by_case[case_id]["passed"] is True, f"{case_id} failed: {by_case[case_id]!r}"


# ---------------------------------------------------------------------------
# Axis 7: CB-08 (Memory/Routines) x Diagnostics Redaction & CB-12
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb08_memory_routines_survive_cb12_sigterm_restart_with_redacted_diagnostics(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """Axis 7: 5-scope memory + routines survive SIGTERM restart; FTS purge & secret redaction."""
    env = qa_env_factory(mock_agy_script=_T3_ADV_MOCK_AGY_SCRIPT, name="t3_cb08_restart")
    canary_secret = "sk-qa-t3-cb08-secret-99887766"

    with env.client() as client:
        r_user = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "op_t3_alpha"},
            json={
                "scope": "user",
                "scope_id": "op_t3_alpha",
                "kind": "preference",
                "title": "T3 Secret Pref",
                "content": f"api_token={canary_secret}",
            },
        )
        assert r_user.status_code == 201
        user_mem_id = str(r_user.json()["id"])

        for hdrs, payload in (
            (
                {"X-Agent-Role": "t3_role"},
                {
                    "scope": "agent_role",
                    "scope_id": "t3_role",
                    "kind": "preference",
                    "title": "Role T3",
                    "content": "Check seals",
                },
            ),
            (
                {"X-Thread-Id": "thr_t3_1"},
                {
                    "scope": "thread",
                    "scope_id": "thr_t3_1",
                    "kind": "dated_observation",
                    "title": "Thread T3",
                    "content": "Observed 2026",
                    "observed_at": "2026-11-27T00:00:00Z",
                    "valid_until": "2026-12-31T23:59:59Z",
                },
            ),
            (
                {"X-Project-Area": "area_t3"},
                {
                    "scope": "project_area",
                    "scope_id": "area_t3",
                    "kind": "source_reference",
                    "title": "Area T3",
                    "content": "Max 3600 RPM",
                },
            ),
            (
                {"X-Actor-Role": "Manager"},
                {
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": "Org T3 SOP",
                    "content": "Lockout first",
                },
            ),
        ):
            assert client.post("/api/v1/memory", headers=hdrs, json=payload).status_code == 201

        rt = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "T3 Survival Routine",
                "instruction": "Verify telemetry",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        assert rt.status_code == 201
        rid = str(rt.json()["id"])
        wkey = str(rt.json()["webhook_key"])

        assert client.post(f"/api/v1/routines/{rid}/test").status_code == 202
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rid}",
                headers={"Authorization": f"Bearer {wkey}"},
                json={"event": "t3"},
            ).status_code
            == 202
        )
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rid}",
                headers={"Authorization": "Bearer wrong-webhook-secret"},
            ).status_code
            == 401
        )

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            runs = client.get(f"/api/v1/routines/{rid}/runs").json()["runs"]
            if len(runs) >= 2 and all(r.get("status") != "running" for r in runs):
                break
            time.sleep(0.1)
        assert len(client.get(f"/api/v1/routines/{rid}/runs").json()["runs"]) >= 2

    # SIGTERM restart
    env.restart(keep_port=False)

    async with env.async_client(timeout=30.0) as aclient:
        # Verify memory & routine runs persisted across restart
        other_user = (
            await aclient.get(
                "/api/v1/memory",
                params={"scope": "user"},
                headers={"X-User-Id": "op_t3_beta"},
            )
        ).json()["items"]
        assert all(it["id"] != user_mem_id for it in other_user)

        runs_after = (await aclient.get(f"/api/v1/routines/{rid}/runs")).json()["runs"]
        assert len(runs_after) >= 2

        exp_json = (
            await aclient.get(
                "/api/v1/memory/export",
                params={"format": "json"},
                headers={"X-User-Id": "op_t3_alpha"},
            )
        ).json()
        assert_no_secret_leak(exp_json, secrets=(canary_secret, env.cap_secret))

        assert (
            await aclient.delete(
                f"/api/v1/memory/{user_mem_id}",
                headers={"X-User-Id": "op_t3_alpha"},
            )
        ).status_code == 200
        fts_after = (
            await aclient.get(
                "/api/v1/memory",
                params={"q": "T3 Secret Pref"},
                headers={"X-User-Id": "op_t3_alpha"},
            )
        ).json()["items"]
        assert all(it["id"] != user_mem_id for it in fts_after)

        diag_fail = (await aclient.get("/api/v1/diagnostics/failures?limit=50")).json()
        assert_no_secret_leak(
            diag_fail, secrets=(canary_secret, wkey, "wrong-webhook-secret", env.cap_secret)
        )

        # Two concurrent post-restart turns have 0 cross-bleed
        turn_a, turn_b = await asyncio.gather(
            trigger_and_wait_turn(
                aclient, "thr_bot_chief", "Run CONCURRENT_TAG=T3_POST_A", timeout=25.0
            ),
            trigger_and_wait_turn(
                aclient, "thr_bot_ops", "Run CONCURRENT_TAG=T3_POST_B", timeout=25.0
            ),
        )
        assert turn_a.assistant_message is not None and turn_b.assistant_message is not None
        assert "T3_POST_A" in str(turn_a.assistant_message["content"])
        assert "T3_POST_B" not in str(turn_a.assistant_message["content"])
        assert "T3_POST_B" in str(turn_b.assistant_message["content"])
        assert "T3_POST_A" not in str(turn_b.assistant_message["content"])

    for fname in ("failures.jsonl", "requests.jsonl"):
        fpath = env.logs_dir / fname
        if fpath.is_file():
            rows = [
                json.loads(line)
                for line in fpath.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert_no_secret_leak(
                rows, secrets=(canary_secret, wkey, "wrong-webhook-secret", env.cap_secret)
            )


@pytest.mark.qa_existing
async def test_t3_cb08_routine_and_cb12_auth_expired_401_pause_resume_zero_duplicate_effects(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """Axis 7: CB-08 routine + CB-12 401 auth_expired pause/resume with 0 duplicate effects."""
    lab = _ControllableLabStack(scada_fixture_mode="auth_expired").start()
    try:
        env = qa_env_factory(
            extra_env=lab.env_vars(),
            mock_agy_script=_T3_ADV_MOCK_AGY_SCRIPT,
            name="t3_cb08_cb12_401",
        )
        async with env.async_client(timeout=40.0) as aclient:
            rt = await aclient.post(
                "/api/v1/bots/bot_chief/routines",
                json={
                    "name": "T3 Chief Routine",
                    "instruction": "CONCURRENT_TAG=CHIEF_RT",
                    "schedule_type": "manual",
                    "enabled": True,
                },
            )
            assert rt.status_code == 201
            rid = str(rt.json()["id"])
            assert (await aclient.post(f"/api/v1/routines/{rid}/test")).status_code == 202

            assert (
                await aclient.patch(
                    "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                )
            ).status_code == 200

            pause_turn = await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                terminal_events=("hitl.approval.requested",),
                timeout=35.0,
            )
            assert isinstance(pause_turn.terminal_event.data, dict)
            appr = pause_turn.terminal_event.data["payload"]["approval"]
            appr_id = str(appr["id"])

            lab.scada_state.set_mode("default")
            resumed_frames: list[SseFrame] = []
            resumed_tid_holder: dict[str, str] = {}
            sse_conn = asyncio.Event()

            async def _listen_resumed() -> None:
                resumed_tid: str | None = None
                async for frame in iter_sse_events(aclient, timeout=35.0, on_connected=sse_conn):
                    resumed_frames.append(frame)
                    if not isinstance(frame.data, dict):
                        continue
                    ev = frame.event_type or frame.event
                    if ev == "turn.started" and frame.data.get("thread_id") == "thr_bot_ops":
                        resumed_tid = str(frame.data.get("turn_id"))
                        resumed_tid_holder["id"] = resumed_tid
                    if (
                        resumed_tid is not None
                        and ev == "message.completed"
                        and frame.data.get("turn_id") == resumed_tid
                    ):
                        return

            task = asyncio.create_task(_listen_resumed())
            try:
                await asyncio.wait_for(sse_conn.wait(), timeout=5.0)
                assert (
                    await aclient.post(
                        f"/api/v1/approvals/{appr_id}/resolve",
                        json={"decision": "allow_once"},
                    )
                ).status_code == 200
                await asyncio.wait_for(task, timeout=35.0)
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            resumed_tid = resumed_tid_holder.get("id")
            assert resumed_tid
            completed = next(
                f
                for f in reversed(resumed_frames)
                if (f.event_type or f.event) == "message.completed"
                and isinstance(f.data, dict)
                and f.data.get("turn_id") == resumed_tid
            )
            assert isinstance(completed.data, dict)
            msg = completed.data["payload"]["message"]
            assert "ALM-3401" in str(msg["content"])
            assert "WO-3408" in str(msg["content"])
            assert (msg.get("metadata") or {}).get("verdict") == "verified"

            bots = (await aclient.get("/api/v1/bots")).json()["bots"]
            assert next(b for b in bots if b["id"] == "bot_ops")["status_state"] == "idle"
            eff = (await aclient.get(f"{lab.effect_sim_url}/api/effects/state")).json()
            assert eff["total_applied"] == 0

            rt_runs = (await aclient.get(f"/api/v1/routines/{rid}/runs")).json()["runs"]
            assert rt_runs
    finally:
        lab.stop()


@pytest.mark.qa_megaplan
def test_t3_megaplan_scan_cb08_cb12_with_log_ingestion_and_redaction(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 7: scan --cases CB-08,CB-12 --ingest-logs correlates request_ids & redacts secrets."""
    canary = "CANARY_T3_SCAN_08_12_TOK"
    with qa_env.client() as client:
        r = client.get(f"/api/v1/threads/missing_t3_08_12/messages?token={canary}")
        assert r.status_code == 404
        req_id = r.headers.get("X-Request-Id", "")
        assert req_id.startswith("req_")

    camp_dir = tmp_path / "camp_axis7"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-08,CB-12",
            "--ingest-logs",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-08", "CB-12"):
        assert case_id in by_case
    assert any(req_id in r.get("request_ids", []) for r in records)

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    assert qa_items
    assert_no_secret_leak(records, secrets=(canary, qa_env.cap_secret))
    assert_no_secret_leak(qa_items, secrets=(canary, qa_env.cap_secret))

    for case_id in ("CB-08", "CB-12"):
        assert by_case[case_id]["passed"] is True, f"{case_id} failed: {by_case[case_id]!r}"


# ---------------------------------------------------------------------------
# Axis 8: CB-09 / CB-10 x Independent Evaluator & QA Queue Deduplication
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb09_cb10_independent_evaluators_with_qa_queue_dedup_and_factory_store(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    tmp_path: Path,
) -> None:
    """Axis 8: CB-09 & CB-10 independent evaluators + FactoryStore backlog/lease fencing."""
    env = qa_env_factory(mock_agy_script=_T3_ADV_MOCK_AGY_SCRIPT, name="t3_cb09_10")
    async with env.async_client(timeout=35.0) as aclient:
        assert (
            await aclient.patch("/api/v1/bots/bot_chief", json={"project_name": "Grokbotclon"})
        ).status_code == 200
        turn_09 = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "CB09_CSV_PROJECT Create csv_to_json.py and test_csv_to_json.py",
            timeout=25.0,
        )
        assert turn_09.assistant_message is not None

        b1 = await aclient.post(
            "/api/v1/bots",
            json={"name": "agent_alpha", "engine_id": "agy", "project_name": "Grokbotclon"},
        )
        b2 = await aclient.post(
            "/api/v1/bots",
            json={"name": "agent_beta", "engine_id": "agy", "project_name": "Grokbotclon"},
        )
        assert b1.status_code == 201 and b2.status_code == 201
        alpha_id, beta_id = str(b1.json()["id"]), str(b2.json()["id"])
        ch = await aclient.post(
            "/api/v1/channels", json={"name": "T3 CB10", "bot_ids": [alpha_id, beta_id]}
        )
        assert ch.status_code == 201
        thr_id = str(ch.json()["thread_id"])
        await trigger_and_wait_turn(
            aclient, thr_id, "@agent_alpha CB10_COLLAB AGENT_ALPHA D1", timeout=25.0
        )
        await trigger_and_wait_turn(
            aclient, thr_id, "@all CB10_COLLAB D2 D3", timeout=30.0
        )

    # CB-09 valid vs naive converter
    cb09_dir = env.projects_root / "Grokbotclon" / "cb09_proj"
    valid_rep = evaluate_csv_to_json_converter(
        [sys.executable, str(cb09_dir / "csv_to_json.py")],
        work_dir=tmp_path / "t3_cb09_valid",
        test_cmd=[sys.executable, "-m", "pytest", "-q", str(cb09_dir / "test_csv_to_json.py")],
    )
    assert valid_rep.passed is True and len(build_cb09_csv_samples()) == 4

    naive_conv = tmp_path / "naive_split.py"
    naive_conv.write_text(
        "import json, sys\n"
        "lines = [line for line in open(sys.argv[1]).read().splitlines() if line.strip()]\n"
        "hdr = lines[0].split(',')\n"
        "open(sys.argv[2], 'w').write(json.dumps([dict(zip(hdr, r.split(','))) "
        "for r in lines[1:]]))\n",
        encoding="utf-8",
    )
    bad_rep = evaluate_csv_to_json_converter(
        [sys.executable, str(naive_conv)], work_dir=tmp_path / "t3_cb09_bad"
    )
    assert bad_rep.passed is False

    # CB-10 3-deliverable build & tests
    spec = build_cb10_three_deliverables_spec()
    cb10_dir = env.projects_root / "Grokbotclon" / spec.project_name
    assert (
        subprocess.run(
            list(spec.build_command), cwd=str(cb10_dir), capture_output=True, check=False
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            list(spec.test_command), cwd=str(cb10_dir), capture_output=True, check=False
        ).returncode
        == 0
    )

    # FactoryStore isolated tracking & lease fencing
    live_db = _REPO_ROOT / "var" / "controlbot.sqlite3"
    store = FactoryStore(tmp_path / "t3_axis8.sqlite3", forbidden_db_paths=(live_db,))
    store.init_db()
    store.add_backlog_item(
        BacklogItem(
            item_id="item-cb09-naive",
            title="Fix naive CSV parser",
            priority=1,
            hypothesis="Use csv.reader and reject ragged rows",
            target_metric="eval_samples",
            baseline_repro_cmd="pytest -q",
        )
    )
    lease = store.acquire_lease("item-cb09-naive", "worker-1", ttl_s=60.0)
    with pytest.raises(FactoryLeaseError):
        store.acquire_lease("item-cb09-naive", "worker-2", ttl_s=60.0)
    store.release_lease(lease.lease_id, lease.generation)


@pytest.mark.qa_megaplan
def test_t3_megaplan_cb09_cb10_scan_and_queue_dedup_with_factory_backlog_link(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 8: Repeated 404 dedups into 1 qa_items row linked to factory_backlog + CB-09/10."""
    camp_dir = tmp_path / "camp_axis8"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    for _ in range(2):
        with qa_env.client() as client:
            assert client.get("/api/v1/threads/missing_t3_cb09_10/messages").status_code == 404
        res = qa_cli_runner.run(
            [
                "scan",
                "--campaign-dir",
                str(camp_dir),
                "--cases",
                "CB-09,CB-10",
                "--ingest-logs",
                "--json",
            ]
        )
        _assert_clean_cli(res)
        assert res.returncode == 0

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    matching = [
        it
        for it in qa_items
        if "missing_t3_cb09_10" in str(it.get("dedup_key", ""))
        or "missing_t3_cb09_10" in str(it.get("normalized_signature", ""))
        or "404" in str(it.get("normalized_signature", ""))
    ]
    assert len(matching) == 1
    assert int(matching[0]["occurrence_count"]) >= 2
    assert matching[0].get("factory_item_id")
    backlog = _query_sqlite_tables(camp_dir, "factory_backlog")
    assert any(b.get("item_id") == matching[0]["factory_item_id"] for b in backlog)

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-09", "CB-10"):
        assert case_id in by_case
        assert by_case[case_id]["passed"] is True, f"{case_id} failed: {by_case[case_id]!r}"


# ---------------------------------------------------------------------------
# Axis 9: CB-11 (facility_a / facility_b SCADA + Maint) x CB-12 (stale / 503 / contradictory)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb11_facility_b_spanish_and_facility_a_with_cb12_stale_503_contradictory(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """Axis 9: facility_a/facility_b parity + ambiguity + stale/503/contradictory + 405 writes."""
    # 1. facility_a (default mode) + 405 write enforcement + 0 effects
    lab_a = LabStack(fixture_mode="default").start()
    try:
        env_a = qa_env_factory(extra_env=lab_a.env_vars(), name="t3_fac_a")
        with httpx.Client(timeout=10.0) as hc:
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                scada_r = hc.request(method, f"{lab_a.scada_url}/api/alarms", json={})
                assert scada_r.status_code == 405
                maint_r = hc.request(method, f"{lab_a.maintenance_url}/api/work_orders", json={})
                assert maint_r.status_code == 405
        async with env_a.async_client(timeout=35.0) as aclient:
            assert (
                await aclient.patch(
                    "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                )
            ).status_code == 200
            t_a = await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )
            assert t_a.assistant_message is not None
            assert "ALM-3401" in str(t_a.assistant_message["content"])
            assert "WO-3408" in str(t_a.assistant_message["content"])
            assert (t_a.assistant_message.get("metadata") or {}).get("verdict") == "verified"
            assert (
                await aclient.get(f"{lab_a.effect_sim_url}/api/effects/state")
            ).json()["total_applied"] == 0
    finally:
        lab_a.stop()

    # 2. facility_b Spanish headers + SC-77/CMMS-77 provenance
    lab_b = LabStack(fixture_mode="facility_b").start()
    try:
        env_b = qa_env_factory(
            extra_env={
                **lab_b.env_vars(),
                "GROKBOT_INSTALLATION_CONFIG": str(
                    _REPO_ROOT / "lab" / "configs" / "facility_b.json"
                ),
            },
            name="t3_fac_b",
        )
        async with env_b.async_client(timeout=35.0) as aclient:
            sub = await aclient.post(
                "/api/tasks",
                json={
                    "query": "Check P-77B alarms and latest work order",
                    "facility_id": "facility-b",
                    "allowed_areas": ["area-2"],
                    "read_only": True,
                },
            )
            assert sub.status_code == 201
            snap = await _poll_task_until_terminal(aclient, str(sub.json()["run_id"]))
            assert snap["run"]["status"] == "succeeded"
            assert "ALM-7701" in str(snap["result"]["answer"])
            assert "WO-7705" in str(snap["result"]["answer"])
            assert {o["source"] for o in snap["result"]["verified_observations"]} == {
                "scada",
                "maintenance",
            }
            assert (
                await aclient.get(f"{lab_b.effect_sim_url}/api/effects/state")
            ).json()["total_applied"] == 0
    finally:
        lab_b.stop()

    # 3. ambiguity pause/resume, stale, down (503), contradictory
    for mode in ("ambiguity", "stale", "down", "contradictory"):
        lab_m = LabStack(fixture_mode=mode).start()
        try:
            env_m = qa_env_factory(extra_env=lab_m.env_vars(), name=f"t3_mode_{mode}")
            async with env_m.async_client(timeout=35.0) as aclient:
                if mode == "ambiguity":
                    sub_amb = await aclient.post(
                        "/api/tasks",
                        json={
                            "query": "Check alarms and work orders for bomba 34",
                            "facility_id": "facility-a",
                            "read_only": True,
                        },
                    )
                    assert sub_amb.status_code == 201
                    rid = str(sub_amb.json()["run_id"])
                    wait_snap = await _poll_task_until_terminal(aclient, rid)
                    assert wait_snap["run"]["status"] == "waiting_for_input"
                    assert (
                        await aclient.post(
                            f"/api/tasks/{rid}/resume", json={"human_input": {"choice": "area-1"}}
                        )
                    ).status_code == 200
                    done_snap = await _poll_task_until_terminal(aclient, rid)
                    assert done_snap["run"]["status"] == "succeeded"
                    assert "ALM-3401" in str(done_snap["result"]["answer"])
                elif mode == "contradictory":
                    sub_c = await aclient.post(
                        "/api/tasks",
                        json={
                            "query": "Check bomba 34 alarms and work orders",
                            "facility_id": "facility-a",
                            "allowed_areas": ["area-1"],
                            "read_only": True,
                        },
                    )
                    assert sub_c.status_code == 201
                    snap_c = await _poll_task_until_terminal(aclient, str(sub_c.json()["run_id"]))
                    assert snap_c["run"]["status"] == "partial"
                    assert len((snap_c.get("result") or {}).get("contradictions", [])) >= 1
                else:
                    assert (
                        await aclient.patch(
                            "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                        )
                    ).status_code == 200
                    t_m = await trigger_and_wait_turn(
                        aclient,
                        "thr_bot_ops",
                        "Check bomba 34 alarms and readings in SCADA and maintenance",
                        timeout=35.0,
                    )
                    assert t_m.assistant_message is not None
                    meta = t_m.assistant_message.get("metadata") or {}
                    if mode == "stale":
                        p_str = json.dumps(meta.get("partial_evidence", []))
                        assert "RDG-STALE-01" in p_str and "RDG-BAD-01" in p_str
                    else:
                        assert meta.get("verdict") != "verified"
                assert (
                    await aclient.get(f"{lab_m.effect_sim_url}/api/effects/state")
                ).json()["total_applied"] == 0
        finally:
            lab_m.stop()


@pytest.mark.qa_megaplan
def test_t3_megaplan_scan_cb11_cb12_cb13_qa5_honest_n3_and_industrial_parity(
    qa_lab_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 9: scan --cases CB-11,CB-12,CB-13 passes CB-11/12 & reports honest CB-13 N3 status."""
    camp_dir = tmp_path / "camp_axis9"
    _run_baseline_to_dir(qa_cli_runner, qa_lab_env, camp_dir, skip_browser=True)

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-11,CB-12,CB-13",
            "--json",
        ]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode in {0, 1, 2, 3}

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    for case_id in ("CB-11", "CB-12", "CB-13"):
        assert case_id in by_case

    n3_probe = qa_cli_runner.run_module("src.n3_probe", ["--json"]).json_stdout()
    if n3_probe["overall_status"] != "READY":
        assert by_case["CB-13"]["passed"] is False
        assert str(by_case["CB-13"].get("blocked_reason") or "").strip()
    else:
        assert by_case["CB-13"]["passed"] is True

    assert by_case["CB-11"]["passed"] is True
    assert by_case["CB-12"]["passed"] is True


# ---------------------------------------------------------------------------
# Axis 10: QA-3 / QA-4 7-Step Repair x PolicyGuard / Cross-Model Audit / Grok Bot Boundary
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t3_qa3_seven_step_repair_rejects_policy_tamper_then_accepts_cross_model_fix(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 10: accept rejects repro tamper & hydrogen/self-audit, then promotes cross-model fix."""
    repo_dir = tmp_path / "qa3_axis10_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "calc.py": "def triple(n: int) -> int:\n    return n\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro_triple.py": (
                "from calc import triple\ndef test_triple() -> None:\n    assert triple(3) == 9\n"
            ),
        },
        with_qa_branch=True,
    )
    tamper_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-tamper-repro",
        files={"test_repro_triple.py": "def test_triple() -> None:\n    assert True\n"},
        base_ref=base_sha,
    )
    clean_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-clean-fix",
        files={"calc.py": "def triple(n: int) -> int:\n    return n * 3\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_qa3_axis10"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    repro_cmd = f"{sys.executable} -m pytest -q test_repro_triple.py"
    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-triple",
                "dedup_key": "CB-00:calc:triple_bug",
                "case_id": "CB-00",
                "subsystem": "calc",
                "normalized_signature": "triple_bug",
                "severity": "P1",
                "state": "reproduced",
                "summary": "calc.triple returns n instead of n*3",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": repro_cmd,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    for cid, csha, br, fmod, auth, aud in (
        (
            "cand-tamper-repro",
            tamper_sha,
            "qa/cand-tamper-repro",
            ["test_repro_triple.py"],
            "hydrogen",
            "pro",
        ),
        ("cand-self-audit", clean_sha, "qa/cand-clean-fix", ["calc.py"], "hydrogen", "hydrogen"),
        ("cand-hydro-audit", clean_sha, "qa/cand-clean-fix", ["calc.py"], "sonnet", "hydrogen"),
        ("cand-clean-fix", clean_sha, "qa/cand-clean-fix", ["calc.py"], "hydrogen", "pro"),
    ):
        (camp_dir / "candidates" / f"{cid}.json").write_text(
            json.dumps(
                {
                    "candidate_id": cid,
                    "item_id": "item-triple",
                    "campaign_id": state["campaign_id"],
                    "base_sha": base_sha,
                    "candidate_sha": csha,
                    "branch_name": br,
                    "files_modified": fmod,
                    "repro_test_path": "test_repro_triple.py",
                    "rerun_command": repro_cmd,
                    "baseline_passed": False,
                    "candidate_passed": True,
                    "audit_passed": True,
                    "author_model": auth,
                    "auditor_model": aud,
                    "status": "candidate_verified" if cid != "cand-clean-fix" else "pending",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    for bad_cid in ("cand-tamper-repro", "cand-self-audit", "cand-hydro-audit"):
        bad_res = qa_cli_runner.run(
            [
                "accept",
                "--campaign-dir",
                str(camp_dir),
                "--candidate",
                bad_cid,
                "--no-build-frontend",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        _assert_clean_cli(bad_res)
        assert bad_res.returncode != 0
        assert _git_head_sha(repo_dir) == base_sha

    reeval = qa_cli_runner.run(
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-triple",
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(reeval)
    assert reeval.returncode == 0

    acc = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-clean-fix",
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(acc)
    assert acc.returncode == 0, f"accept failed: {acc.stderr}\n{acc.stdout}"
    assert _git_head_sha(repo_dir) == clean_sha
    cand_after = json.loads((camp_dir / "candidates" / "cand-clean-fix.json").read_text())
    assert cand_after["status"] == "accepted_qa"

    rep = qa_cli_runner.run(["report", "--campaign-dir", str(camp_dir), "--json"])
    _assert_clean_cli(rep)
    assert rep.returncode == 0
    stats = rep.json_stdout()["stats"]
    assert stats["repaired_passing_full_gate"] >= 1
    assert stats["open_p0"] == 0


@pytest.mark.qa_megaplan
def test_t3_qa4_parallel_two_repairers_integrator_rebase_and_rollback_on_regression(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 10: repair --max-parallel 2 + serialized rebase + auto-rollback + manual rollback."""
    repo_dir = tmp_path / "qa4_axis10_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "mod_a.py": "def fn_a() -> str:\n    return 'broken_a'\n",
            "mod_b.py": "def fn_b() -> str:\n    return 'broken_b'\n",
            "shared_gate.py": "def gate_ok() -> bool:\n    return True\n",
            "test_smoke.py": (
                "from shared_gate import gate_ok\ndef test_smoke() -> None:\n    assert gate_ok()\n"
            ),
            "test_a.py": (
                "from mod_a import fn_a\ndef test_a() -> None:\n    assert fn_a() == 'ok_a'\n"
            ),
            "test_b.py": (
                "from mod_b import fn_b\ndef test_b() -> None:\n    assert fn_b() == 'ok_b'\n"
            ),
        },
        with_qa_branch=True,
    )
    regress_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-regress",
        files={"shared_gate.py": "def gate_ok() -> bool:\n    return False\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_qa4_axis10"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-qa4-a",
                        "dedup_key": "CB-05:mod_a:broken_a",
                        "case_id": "CB-05",
                        "subsystem": "mod_a",
                        "normalized_signature": "broken_a",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_a returns broken_a",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_a.py",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-qa4-b",
                        "dedup_key": "CB-06:mod_b:broken_b",
                        "case_id": "CB-06",
                        "subsystem": "mod_b",
                        "normalized_signature": "broken_b",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_b returns broken_b",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_b.py",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with _mock_repairer_env(qa_cli_runner.fake_home) as repairer_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "2",
                "--max-attempts",
                "2",
                "--no-auto-accept",
                "--no-build-frontend",
                "--repo-root",
                str(repo_dir),
            ],
            env_overrides=repairer_env,
            cwd=repo_dir,
        )
    _assert_clean_cli(rep_res)
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"

    verified_files = sorted((camp_dir / "candidates").glob("*.json"))
    verified_ids = [
        json.loads(cf.read_text(encoding="utf-8"))["candidate_id"]
        for cf in verified_files
        if json.loads(cf.read_text(encoding="utf-8")).get("status") == "candidate_verified"
    ]
    assert len(verified_ids) == 2

    acc1 = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            verified_ids[0],
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
            "--json",
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(acc1)
    assert acc1.returncode == 0
    sha1 = str(acc1.json_stdout()["accepted_sha"])

    acc2 = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            verified_ids[1],
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
            "--json",
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(acc2)
    assert acc2.returncode == 0
    sha2 = str(acc2.json_stdout()["accepted_sha"])
    assert sha2 != sha1
    anc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha1, sha2], cwd=str(repo_dir), check=False
    )
    assert anc.returncode == 0, "Second accepted candidate did not rebase onto first QA SHA"

    # Seed 3rd regressing candidate -> accept triggers automatic rollback preserving sha2
    (camp_dir / "candidates" / "cand-regress.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-regress",
                "item_id": "item-regress",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": regress_sha,
                "branch_name": "qa/cand-regress",
                "files_modified": ["shared_gate.py"],
                "rerun_command": f"{sys.executable} -m pytest -q test_a.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "candidate_verified",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    reg_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-regress",
            "--no-build-frontend",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(reg_res)
    assert reg_res.returncode != 0
    assert _git_head_sha(repo_dir) == sha2
    assert (
        json.loads((camp_dir / "candidates" / "cand-regress.json").read_text(encoding="utf-8"))[
            "status"
        ]
        == "rolled_back"
    )

    # Manual rollback of 2nd accepted candidate restores sha1
    rb_res = qa_cli_runner.run(
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            verified_ids[1],
            "--repo-root",
            str(repo_dir),
            "--json",
        ],
        cwd=repo_dir,
    )
    _assert_clean_cli(rb_res)
    assert rb_res.returncode == 0
    assert _git_head_sha(repo_dir) == sha1


@pytest.mark.qa_megaplan
def test_t3_grok_bot_main_test_boundary_and_ref_unavailable_with_repair_resume(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 10: Grok Bot {main, test} boundary + REF_UNAVAILABLE + rotated .1 log resume."""
    for bad_bot in ("work", "prod", "custom", "Main"):
        with pytest.raises(ValueError):
            build_grok_bot_reference_card(bot_name=bad_bot, case_id="CB-00")
    unavail = build_grok_bot_reference_card(
        bot_name="test", case_id="CB-00", available=False, unavailable_reason="Headless lab"
    )
    assert unavail.status == "REF_UNAVAILABLE"

    camp_dir = tmp_path / "camp_axis10_ref"
    state = _run_baseline_to_dir(
        qa_cli_runner,
        qa_env,
        camp_dir,
        lane="external_reference",
        log_dir=qa_env.logs_dir,
        skip_browser=True,
    )

    with qa_env.client() as client:
        assert client.get("/api/v1/bots/t3_pre_rot/library").status_code == 404

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs", "--json"]
    )
    _assert_clean_cli(scan_res)
    assert scan_res.returncode == 0

    card_files = sorted((camp_dir / "reference_cards").glob("*.json"))
    assert card_files
    for cf in card_files:
        card = json.loads(cf.read_text(encoding="utf-8"))
        assert card.get("bot_used") in {"main", "test", None}
        assert_no_secret_leak(card, secrets=(qa_env.cap_secret,))

    # Rotate failures.jsonl -> .1 with unread tail + new active entry + non-zero attempts/leases
    state = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    state["attempts"] = {"item-t3-resume": 1}
    state["active_leases"] = {"item-t3-resume": "lease-gen-4"}
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    failures_file = qa_env.logs_dir / "failures.jsonl"
    rotated_file = qa_env.logs_dir / "failures.jsonl.1"
    with failures_file.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "id": "fail_t3_rot_tail",
                    "ts": "2026-11-27T07:00:00Z",
                    "source": "pages",
                    "kind": "page_render_error",
                    "message": "POST /api/v1/pages/t3_tail -> HTTP 404",
                    "path": "/api/v1/pages/t3_tail",
                    "method": "POST",
                    "status_code": 404,
                    "request_id": "req_t3_tail_01",
                }
            )
            + "\n"
        )
    os.replace(failures_file, rotated_file)
    failures_file.write_text(
        json.dumps(
            {
                "id": "fail_t3_rot_active",
                "ts": "2026-11-27T07:00:01Z",
                "source": "routines",
                "kind": "routine_dispatch_error",
                "message": "GET /api/v1/routines/t3_active -> HTTP 500",
                "path": "/api/v1/routines/t3_active",
                "method": "GET",
                "status_code": 500,
                "request_id": "req_t3_active_02",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    res_resume = qa_cli_runner.run(["resume", "--campaign-dir", str(camp_dir), "--json"])
    _assert_clean_cli(res_resume)
    assert res_resume.returncode == 0
    after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert after["attempts"]["item-t3-resume"] >= 1
    assert after["active_leases"].get("item-t3-resume")

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    blob = json.dumps(qa_items)
    assert "req_t3_tail_01" in blob and "req_t3_active_02" in blob


@pytest.mark.qa_megaplan
def test_t3_grok_bot_fixture_override_and_p0_halt_blocks_repair_lane(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Axis 10: Dynamic CB-VALVE-104 beats stale ref; ingested P0 halts scan & repair."""
    catalog = build_cb_valve_104_catalog()
    camp_dir = tmp_path / "camp_axis10_p0"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    (camp_dir / "fixtures").mkdir(parents=True, exist_ok=True)
    (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(
            {
                "fixture_version": catalog.fixture_version,
                "sku": catalog.sku,
                "active_price": str(catalog.active_record.price),
                "prior_price": str(catalog.prior_record.price),
                "currency": catalog.active_record.currency,
                "source_url": catalog.active_record.source_url,
                "records": catalog.to_json_records(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (camp_dir / "reference_cards").mkdir(parents=True, exist_ok=True)
    ref_payload = build_grok_bot_reference_card(bot_name="main", case_id="CB-02").to_dict()
    ref_dict: dict[str, Any] = {
        **ref_payload,
        "conditions": {
            "timing_comparability": "observational_only_different_hardware_and_cloud_backend",
            "privacy_scope": "main_and_test_only_no_tokens_cookies_or_asar_reverse_engineering",
        },
    }
    (camp_dir / "reference_cards" / "ref-cb02-main.json").write_text(
        json.dumps(ref_dict, indent=2),
        encoding="utf-8",
    )

    cb02_scan = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-02", "--json"]
    )
    _assert_clean_cli(cb02_scan)
    assert cb02_scan.returncode == 0
    cb02_recs = [r for r in _load_megaplan_run_records(camp_dir) if r.get("case_id") == "CB-02"]
    assert cb02_recs
    cb02_latest = cb02_recs[-1]
    assert cb02_latest.get("fixture_version") == catalog.fixture_version

    # Append a P0 marker log record -> scan exits 1 (halted_p0) -> repair halts
    failures_log = qa_env.logs_dir / "failures.jsonl"
    failures_log.parent.mkdir(parents=True, exist_ok=True)
    with failures_log.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "id": "fail_t3_p0_secret_leak",
                    "ts": "2026-11-27T07:10:00Z",
                    "source": "isolation",
                    "kind": "secret_leak",
                    "message": "Simulated secret_leak P0 boundary violation",
                    "request_id": "req_t3_p0_01",
                }
            )
            + "\n"
        )

    p0_scan = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs", "--json"]
    )
    _assert_clean_cli(p0_scan)
    assert p0_scan.returncode == 1
    assert (
        json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))["status"]
        == "halted_p0"
    )

    rep_halt = qa_cli_runner.run(
        ["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "1", "--no-build-frontend"]
    )
    halt_comb = _assert_clean_cli(rep_halt)
    assert rep_halt.returncode != 0
    assert any(tok in halt_comb for tok in ("p0", "halted_p0", "halt"))

    assert cb02_latest["passed"] is True, f"CB-02 scenario failed: {cb02_latest!r}"


# ---------------------------------------------------------------------------
# Cross-Axis (2 x 5 & 9 x 10)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t3_cb00_cb05_active_mime_xss_defense_under_auth_with_strict_browser_and_diagnostics(
    qa_auth_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Cross-Axis (2 x 5): Active-MIME XSS headers + auth StrictBrowserPage + zero token leaks."""
    token = qa_auth_env.web_token
    assert token is not None

    samples: list[tuple[str, str, bytes]] = [
        ("t3_xss.html", "text/html", b"<html><script>alert(1)</script></html>"),
        ("t3_vec.svg", "image/svg+xml", b"<svg onload='alert(1)'></svg>"),
        ("t3_evil.js", "application/javascript", b"alert('xss');"),
    ]
    with qa_auth_env.client() as client:
        for fname, mime, payload in samples:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert up.status_code == 201
            dl = client.get(f"/api/v1/attachments/{up.json()['id']}")
            assert dl.status_code == 200
            assert dl.headers.get("X-Content-Type-Options") == "nosniff"
            assert dl.headers.get("Content-Security-Policy") == "sandbox; default-src 'none'"
            assert dl.headers.get("Content-Disposition", "").startswith("attachment;")

        miss = client.get("/api/v1/attachments/att_missing_t3_xss")
        assert miss.status_code == 404
        assert miss.headers.get("X-Request-Id", "").startswith("req_")

    with httpx.Client(base_url=qa_auth_env.base_url, timeout=10.0) as anon:
        assert anon.get("/api/v1/bots/bot_chief/library").status_code == 401

    surface = await assert_react_app_surface(
        qa_auth_env.base_url, strict_browser_page, web_token=token
    )
    assert surface["title"] == "Grok Bot — ControlBot Studio"

    with qa_auth_env.client() as client:
        for ep in (
            "/api/v1/diagnostics/summary",
            "/api/v1/diagnostics/failures?limit=100",
            "/api/v1/diagnostics/requests?limit=100",
        ):
            assert_no_secret_leak(client.get(ep).json(), secrets=(token, qa_auth_env.cap_secret))

    for fname in ("failures.jsonl", "requests.jsonl"):
        fpath = qa_auth_env.logs_dir / fname
        if fpath.is_file():
            rows = [
                json.loads(line)
                for line in fpath.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert_no_secret_leak(rows, secrets=(token, qa_auth_env.cap_secret))

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_t3_cb12_concurrent_runs_plus_cb11_lab_and_cb13_n3_probe_isolation(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    qa_cli_runner: QACliRunner,
) -> None:
    """Cross-Axis (9 x 10): Concurrent chat + CB-11 SCADA/Maint + N3 probe + live isolation."""
    lab = LabStack(fixture_mode="default").start()
    try:
        env = qa_env_factory(
            extra_env=lab.env_vars(),
            mock_agy_script=_T3_ADV_MOCK_AGY_SCRIPT,
            name="t3_cross_9_10",
        )
        async with env.async_client(timeout=40.0) as aclient:
            assert (
                await aclient.patch(
                    "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                )
            ).status_code == 200

            chat_turn, scada_turn = await asyncio.gather(
                trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    "Run CONCURRENT_TAG=T3_CHIEF_99",
                    timeout=35.0,
                ),
                trigger_and_wait_turn(
                    aclient,
                    "thr_bot_ops",
                    "Check bomba 34 alarms and readings in SCADA and maintenance",
                    timeout=35.0,
                ),
            )
            assert chat_turn.assistant_message is not None
            assert scada_turn.assistant_message is not None
            chat_body = str(chat_turn.assistant_message["content"])
            scada_body = str(scada_turn.assistant_message["content"])
            assert "T3_CHIEF_99" in chat_body and "ALM-3401" not in chat_body
            assert "ALM-3401" in scada_body and "WO-3408" in scada_body
            assert "T3_CHIEF_99" not in scada_body
            assert (scada_turn.assistant_message.get("metadata") or {}).get("verdict") == (
                "verified"
            )
            assert (
                await aclient.get(f"{lab.effect_sim_url}/api/effects/state")
            ).json()["total_applied"] == 0

        env.assert_isolated_from_live()
    finally:
        lab.stop()

    probe_res = qa_cli_runner.run_module("src.n3_probe", ["--json"])
    assert probe_res.returncode in {0, 2}
    probe_json = probe_res.json_stdout()
    assert probe_json["overall_status"] in {"READY", "PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM"}
    strict_res = qa_cli_runner.run_module("src.n3_probe", ["--strict", "--json"])
    if probe_json["overall_status"] == "READY":
        assert strict_res.returncode == 0
    else:
        assert strict_res.returncode != 0
