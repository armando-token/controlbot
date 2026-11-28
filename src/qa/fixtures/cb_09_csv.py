"""Adversarial CSV-to-JSON samples and independent subprocess evaluator for CB-09."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CB09CsvSample:
    """Single CSV-to-JSON independent evaluation sample."""

    name: str
    csv_text: str
    expected_rows: tuple[dict[str, str], ...] | None
    expect_error: bool
    description: str


@dataclass(frozen=True)
class CB09SampleResult:
    """Outcome of running a candidate CSV converter on one CB-09 sample."""

    name: str
    passed: bool
    returncode: int
    detail: str


@dataclass(frozen=True)
class CB09EvalReport:
    """Aggregate report from the independent CB-09 CSV-to-JSON evaluator."""

    passed: bool
    sample_results: tuple[CB09SampleResult, ...]
    project_tests_passed: bool | None = None
    project_tests_output: str = ""


def build_cb09_csv_samples() -> tuple[CB09CsvSample, ...]:
    """Return adversarial CSV edge-case samples for CB-09 converter evaluation."""
    return (
        CB09CsvSample(
            name="empty_lines",
            csv_text="sku,name,qty\n\nCB-1,Valve,4\n   \nCB-2,Gauge,9\n\n",
            expected_rows=(
                {"sku": "CB-1", "name": "Valve", "qty": "4"},
                {"sku": "CB-2", "name": "Gauge", "qty": "9"},
            ),
            expect_error=False,
            description="Header + rows separated by empty and whitespace-only lines.",
        ),
        CB09CsvSample(
            name="quoted_fields",
            csv_text=(
                "sku,name,notes\n"
                'CB-10,"Valve, High-P","Sensor ""A1"""\n'
                'CB-11,"Line1\nLine2","Ok"\n'
            ),
            expected_rows=(
                {"sku": "CB-10", "name": "Valve, High-P", "notes": 'Sensor "A1"'},
                {"sku": "CB-11", "name": "Line1\nLine2", "notes": "Ok"},
            ),
            expect_error=False,
            description="Quoted commas, escaped double-quotes, and embedded newlines.",
        ),
        CB09CsvSample(
            name="invalid_malformed",
            csv_text='sku,name,qty\nCB-20,"Unterminated quote\nONLY_ONE_COL\n',
            expected_rows=None,
            expect_error=True,
            description="Malformed row width + unterminated quote must fail with non-zero exit.",
        ),
        CB09CsvSample(
            name="utf8_and_whitespace",
            csv_text="sku,name,qty\nCB-34,Válvula Nº 34,12\n",
            expected_rows=({"sku": "CB-34", "name": "Válvula Nº 34", "qty": "12"},),
            expect_error=False,
            description="UTF-8 accented Spanish characters preserved cleanly.",
        ),
    )


def evaluate_csv_to_json_converter(
    converter_cmd: Sequence[str],
    *,
    work_dir: Path,
    test_cmd: Sequence[str] | None = None,
    test_cwd: Path | None = None,
    timeout_s: float = 30.0,
) -> CB09EvalReport:
    """Independently run and validate a CB-09 CSV-to-JSON converter and optional tests."""
    work_dir.mkdir(parents=True, exist_ok=True)
    samples = build_cb09_csv_samples()
    results: list[CB09SampleResult] = []

    for sample in samples:
        csv_path = work_dir / f"{sample.name}.csv"
        out_path = work_dir / f"{sample.name}.json"
        csv_path.write_text(sample.csv_text, encoding="utf-8")
        if out_path.exists():
            out_path.unlink()

        try:
            proc = subprocess.run(
                [*converter_cmd, str(csv_path), str(out_path)],
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=False,
                    returncode=-1,
                    detail=f"Converter execution failed: {type(exc).__name__}: {exc}",
                )
            )
            continue

        if sample.expect_error:
            ok = proc.returncode != 0
            detail = (
                "Rejected malformed CSV cleanly."
                if ok
                else "Converter exited 0 on malformed CSV!"
            )
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=ok,
                    returncode=proc.returncode,
                    detail=detail,
                )
            )
            continue

        if proc.returncode != 0:
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=False,
                    returncode=proc.returncode,
                    detail=f"Non-zero exit {proc.returncode}: {proc.stderr.strip()}",
                )
            )
            continue

        raw_json = (
            out_path.read_text(encoding="utf-8") if out_path.is_file() else proc.stdout
        )
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            results.append(
                CB09SampleResult(
                    name=sample.name,
                    passed=False,
                    returncode=proc.returncode,
                    detail=f"Invalid JSON output: {exc}",
                )
            )
            continue

        expected_list = list(sample.expected_rows or ())
        ok = parsed == expected_list
        detail = (
            "Exact row match."
            if ok
            else f"Row mismatch: got {parsed!r}, expected {expected_list!r}"
        )
        results.append(
            CB09SampleResult(
                name=sample.name,
                passed=ok,
                returncode=proc.returncode,
                detail=detail,
            )
        )

    project_tests_passed: bool | None = None
    project_tests_output = ""
    if test_cmd is not None:
        resolved_test_cwd = test_cwd if test_cwd is not None else work_dir
        try:
            test_proc = subprocess.run(
                list(test_cmd),
                cwd=str(resolved_test_cwd),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            project_tests_passed = test_proc.returncode == 0
            project_tests_output = (test_proc.stdout + "\n" + test_proc.stderr).strip()
        except (OSError, subprocess.SubprocessError) as exc:
            project_tests_passed = False
            project_tests_output = f"Project test execution failed: {type(exc).__name__}: {exc}"

    all_samples_ok = all(r.passed for r in results)
    overall_ok = all_samples_ok and (project_tests_passed is not False)
    return CB09EvalReport(
        passed=overall_ok,
        sample_results=tuple(results),
        project_tests_passed=project_tests_passed,
        project_tests_output=project_tests_output,
    )


__all__ = [
    "CB09CsvSample",
    "CB09EvalReport",
    "CB09SampleResult",
    "build_cb09_csv_samples",
    "evaluate_csv_to_json_converter",
]
