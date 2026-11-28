"""CB-09 scenario runner: CSV-to-JSON code project + independent edge-case evaluator."""

from __future__ import annotations

import contextlib
import sys
from typing import Any

from src.factory.errors import IsolationBoundaryError
from src.qa.fixtures.cb_09_csv import CB09EvalReport, evaluate_csv_to_json_converter
from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ProjectsRootUnavailableError,
    ScenarioContext,
    TurnOutcome,
    cleanup_project_subpath_http,
    fetch_project_tree_http,
    finalize_scenario,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import measure_ux_action

_REFERENCE_CSV_TO_JSON = '''"""Convert UTF-8 CSV to JSON array with strict header/row validation."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path


def convert_csv_to_json(csv_path: Path, out_path: Path) -> None:
    raw = csv_path.read_text(encoding="utf-8-sig")
    # Reject unterminated double quotes before csv.reader silently absorbs EOF
    quote_count = 0
    for ch in raw:
        if ch == '"':
            quote_count += 1
    if quote_count % 2 != 0:
        raise ValueError("Unterminated quoted field in CSV.")

    if not raw.strip():
        raise ValueError("Empty CSV file.")

    reader = csv.reader(io.StringIO(raw, newline=""), dialect="excel", strict=True)
    rows_raw = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows_raw:
        raise ValueError("Missing CSV header.")

    header = rows_raw[0]
    records: list[dict[str, str]] = []
    for row in rows_raw[1:]:
        if len(row) != len(header):
            raise ValueError(f"Row column count {len(row)} != header count {len(header)}")
        records.append(dict(zip(header, row, strict=True)))

    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: csv_to_json.py <input.csv> <output.json>", file=sys.stderr)
        return 2
    try:
        convert_csv_to_json(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print(f"CSV error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_REFERENCE_CSV_TESTS = '''"""Unit tests for csv_to_json converter."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_csv_to_json_roundtrip(tmp_path: Path) -> None:
    csv_file = tmp_path / "sample.csv"
    out_file = tmp_path / "out.json"
    csv_file.write_text('sku,name,qty\\n\\nCB-1,"Valve, High",2\\n', encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("csv_to_json.py")),
            str(csv_file),
            str(out_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(out_file.read_text(encoding="utf-8")) == [
        {"sku": "CB-1", "name": "Valve, High", "qty": "2"}
    ]
'''


async def _run_cb09_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "code_project"
    work_dir = ctx.isolated_work_dir()
    orig_project_name: str | None = None
    orig_had_chief = False
    patched_project = False

    try:
        async with ctx.async_client(timeout=35.0) as aclient:
            if ctx.caps.is_live_agent_target:
                bots_resp = await aclient.get("/api/v1/bots")
                ctx.add_request_id(bots_resp)
                if bots_resp.status_code == 200:
                    chief = next(
                        (
                            b
                            for b in safe_response_dict(bots_resp).get("bots", [])
                            if isinstance(b, dict) and b.get("id") == "bot_chief"
                        ),
                        None,
                    )
                    if chief is not None:
                        orig_had_chief = True
                        orig_project_name = chief.get("project_name")

                patch_r = await aclient.patch(
                    "/api/v1/bots/bot_chief", json={"project_name": "Grokbotclon"}
                )
                patched_project = patch_r.status_code == 200
                ctx.assertions["bot_project_patched"] = patched_project
                try:
                    await cleanup_project_subpath_http(
                        aclient,
                        project_rel_root="cb09_proj",
                        project_name="Grokbotclon",
                        repo_root=ctx.repo_root,
                    )
                except ProjectsRootUnavailableError as exc:
                    ctx.assertions["studio_projects_api_200"] = False
                    ctx.error_notes.append(str(exc))
                    ctx.clarity_notes = str(exc)
                    return

                async def _run_turn() -> TurnOutcome:
                    return await trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        "CB09_CSV_PROJECT Create csv_to_json.py and test_csv_to_json.py",
                        timeout=30.0,
                    )

                turn, timing = await measure_ux_action(_run_turn, actions_to_reach=1)
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.message_id = str(turn.user_message.get("id") or "")

                # Fetch files written by agy into cb09_proj via Studio HTTP API (never fabricate!)
                fetched = await fetch_project_tree_http(
                    aclient,
                    project_rel_root="cb09_proj",
                    dest_dir=work_dir,
                    project_name="Grokbotclon",
                )
                converter_path = work_dir / "csv_to_json.py"
                test_path = work_dir / "test_csv_to_json.py"
                has_converter = converter_path.is_file()
                has_tests = test_path.is_file()
                ctx.assertions["deliverable_converter_exists"] = has_converter
                ctx.assertions["deliverable_tests_exist"] = has_tests
                if not has_converter or not has_tests:
                    ctx.error_notes.append(
                        "CB-09 agent output did not create runnable csv_to_json.py and "
                        f"test_csv_to_json.py (fetched={fetched!r})."
                    )
                    ctx.evidence = {"fetched_files": fetched, "reply": turn.reply_text}
                    ctx.clarity_notes = ctx.error_notes[-1]
                    return
            else:
                # Probe /api/projects on Studio target, then run deterministic converter harness
                r_proj = await aclient.get("/api/projects")
                ctx.add_request_id(r_proj)
                ctx.assertions["studio_projects_api_200"] = r_proj.status_code == 200
                converter_path = work_dir / "csv_to_json.py"
                test_path = work_dir / "test_csv_to_json.py"
                converter_path.write_text(_REFERENCE_CSV_TO_JSON, encoding="utf-8")
                test_path.write_text(_REFERENCE_CSV_TESTS, encoding="utf-8")
                ctx.assertions["deliverable_converter_exists"] = True
                ctx.assertions["deliverable_tests_exist"] = True

        # Independent subprocess evaluation against all 4 adversarial samples + pytest
        async def _eval_subproc() -> CB09EvalReport:
            return evaluate_csv_to_json_converter(
                [sys.executable, str(converter_path)],
                work_dir=work_dir / "eval_tmp",
                test_cmd=[sys.executable, "-m", "pytest", "-q", str(test_path)],
                test_cwd=work_dir,
            )

        report, eval_timing = await measure_ux_action(_eval_subproc, actions_to_reach=1)
        if ctx.ttfp_ms is None:
            ctx.ttfp_ms = eval_timing.ttfp_ms
            ctx.completion_ms = eval_timing.completion_ms

        for sample_res in report.sample_results:
            ctx.assertions[f"sample_{sample_res.name}"] = sample_res.passed
            if not sample_res.passed:
                ctx.error_notes.append(f"Sample {sample_res.name}: {sample_res.detail}")

        tests_ok = report.project_tests_passed is True
        ctx.assertions["project_pytest_passed"] = tests_ok
        if not tests_ok:
            ctx.error_notes.append(
                f"CB-09 pytest failed: {report.project_tests_output[:240]}"
            )

        ctx.evidence = {
            "work_dir": str(work_dir),
            "samples": [
                {"name": s.name, "passed": s.passed, "detail": s.detail}
                for s in report.sample_results
            ],
            "project_tests_passed": report.project_tests_passed,
        }
        ctx.clarity_notes = (
            "CB-09 CSV->JSON converter & pytest verified against 4 adversarial samples."
        )
    finally:
        if patched_project and orig_had_chief:
            with contextlib.suppress(Exception), ctx.sync_client() as c:
                c.patch("/api/v1/bots/bot_chief", json={"project_name": orig_project_name})
        if ctx.caps.is_live_agent_target:
            try:
                async with ctx.async_client(timeout=15.0) as cleanup_client:
                    await cleanup_project_subpath_http(
                        cleanup_client,
                        project_rel_root="cb09_proj",
                        project_name="Grokbotclon",
                        repo_root=ctx.repo_root,
                    )
            except ProjectsRootUnavailableError as exc:
                ctx.assertions.setdefault("studio_projects_api_200", False)
                note = str(exc)
                if note not in ctx.error_notes:
                    ctx.error_notes.append(note)
            except IsolationBoundaryError:
                raise
            except Exception:
                pass


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-09 scenario."""
    run_coro_sync(_run_cb09_async(ctx))
    return finalize_scenario(ctx)
