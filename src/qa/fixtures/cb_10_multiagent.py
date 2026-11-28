"""Three-deliverable two-agent project spec and independent build/test evaluator for CB-10."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class CB10DeliverableSpec:
    """Single deliverable contract for CB-10 two-agent collaboration."""

    deliverable_id: str
    rel_path: str
    assigned_agent: Literal["agent_alpha", "agent_beta"]
    description: str
    required_symbols: tuple[str, ...]


@dataclass(frozen=True)
class CB10ProjectSpec:
    """Synthetic 3-deliverable multi-file project spec for CB-10."""

    project_name: str
    agents: tuple[str, str]
    deliverables: tuple[CB10DeliverableSpec, CB10DeliverableSpec, CB10DeliverableSpec]
    build_command: tuple[str, ...]
    test_command: tuple[str, ...]


def build_cb10_three_deliverables_spec() -> CB10ProjectSpec:
    """Build the 3-deliverable, 2-agent synthetic project contract for CB-10."""
    return CB10ProjectSpec(
        project_name="cb10_summary_pkg",
        agents=("agent_alpha", "agent_beta"),
        deliverables=(
            CB10DeliverableSpec(
                deliverable_id="D1",
                rel_path="src_pkg/calc.py",
                assigned_agent="agent_alpha",
                description="Core numeric summary computation helper.",
                required_symbols=("compute_summary",),
            ),
            CB10DeliverableSpec(
                deliverable_id="D2",
                rel_path="src_pkg/cli.py",
                assigned_agent="agent_beta",
                description="CLI entrypoint integrating compute_summary from agent_alpha.",
                required_symbols=("main", "compute_summary"),
            ),
            CB10DeliverableSpec(
                deliverable_id="D3",
                rel_path="tests/test_calc_cli.py",
                assigned_agent="agent_beta",
                description="End-to-end unit/CLI roundtrip tests.",
                required_symbols=("test_summary_cli_roundtrip",),
            ),
        ),
        build_command=(sys.executable, "-m", "compileall", "-q", "src_pkg"),
        test_command=(sys.executable, "-m", "pytest", "-q"),
    )


_INDEPENDENT_VERIFY_SCRIPT = """
import ast as _ast
import contextlib
import inspect
import io
import json
import math
import runpy as _runpy
import sys
import warnings as _warnings
import src_pkg.calc as _calc_mod
import src_pkg.cli as _cli_mod
from src_pkg.calc import compute_summary
from src_pkg.cli import main


def _check_summary_payload(payload, expected_vals, label):
    if not isinstance(payload, dict) or "sum" not in payload:
        raise AssertionError(f"{label} returned invalid payload: {payload!r}")
    exp_sum = sum(expected_vals)
    exp_count = float(len(expected_vals))
    exp_mean = exp_sum / exp_count
    exp_min = min(expected_vals)
    exp_max = max(expected_vals)
    if not math.isclose(float(payload["sum"]), exp_sum, rel_tol=1e-6, abs_tol=1e-6):
        raise AssertionError(f"{label} sum mismatch (expected {exp_sum}): {payload!r}")
    if "count" in payload and not math.isclose(
        float(payload["count"]), exp_count, rel_tol=1e-6, abs_tol=1e-6
    ):
        raise AssertionError(f"{label} count mismatch (expected {exp_count}): {payload!r}")
    for avg_key in ("mean", "avg"):
        if avg_key in payload and not math.isclose(
            float(payload[avg_key]), exp_mean, rel_tol=1e-6, abs_tol=1e-6
        ):
            raise AssertionError(
                f"{label} {avg_key} mismatch (expected {exp_mean}): {payload!r}"
            )
    if "min" in payload and not math.isclose(
        float(payload["min"]), exp_min, rel_tol=1e-6, abs_tol=1e-6
    ):
        raise AssertionError(f"{label} min mismatch (expected {exp_min}): {payload!r}")
    if "max" in payload and not math.isclose(
        float(payload["max"]), exp_max, rel_tol=1e-6, abs_tol=1e-6
    ):
        raise AssertionError(f"{label} max mismatch (expected {exp_max}): {payload!r}")


def _vals_match(actual_vals, expected_vals):
    if not isinstance(actual_vals, (list, tuple)) or len(actual_vals) != len(expected_vals):
        return False
    try:
        return all(
            math.isclose(float(a), float(b), rel_tol=1e-6, abs_tol=1e-6)
            for a, b in zip(actual_vals, expected_vals)
        )
    except (TypeError, ValueError):
        return False


def _payloads_match(cli_payload, calc_ret):
    if not isinstance(cli_payload, dict) or not isinstance(calc_ret, dict):
        return False
    if "sum" not in calc_ret or "sum" not in cli_payload:
        return False
    for key, calc_val in calc_ret.items():
        if key not in cli_payload:
            return False
        cli_val = cli_payload[key]
        if isinstance(calc_val, (int, float)) and isinstance(cli_val, (int, float)):
            if not math.isclose(float(cli_val), float(calc_val), rel_tol=1e-6, abs_tol=1e-6):
                return False
        elif cli_val != calc_val:
            return False
    return True


def _extract_cli_payload(out_txt, ret, label):
    trimmed = out_txt.strip() if isinstance(out_txt, str) else ""
    if trimmed:
        try:
            parsed = json.loads(trimmed)
        except json.JSONDecodeError:
            parsed = json.loads(trimmed.splitlines()[-1])
        if ret not in (0, None):
            raise AssertionError(f"{label} returned non-zero status: {ret!r}")
        return parsed
    if isinstance(ret, dict):
        return ret
    raise AssertionError(f"{label} produced neither JSON stdout nor dict (ret={ret!r})")


_check_summary_payload(compute_summary([2.0, 4.0, 6.0]), [2.0, 4.0, 6.0], "compute_summary[2,4,6]")
_check_summary_payload(compute_summary([3.0, 5.0]), [3.0, 5.0], "compute_summary[3,5]")

_orig_compute = _calc_mod.compute_summary
_invocations = []


def _materialize_seq(val):
    if isinstance(val, (list, tuple)):
        return val
    if not isinstance(val, (str, bytes, dict)) and hasattr(val, "__iter__"):
        return list(val)
    return val


def _wrapped_compute(*args, **kwargs):
    fwd_args = tuple(_materialize_seq(a) if idx == 0 else a for idx, a in enumerate(args))
    fwd_kwargs = {k: _materialize_seq(v) for k, v in kwargs.items()}
    try:
        bound = inspect.signature(_orig_compute).bind(*fwd_args, **fwd_kwargs)
        bound.apply_defaults()
        raw_first = next(iter(bound.arguments.values()), ())
    except Exception:
        raw_first = fwd_args[0] if fwd_args else next(iter(fwd_kwargs.values()), ())
    vals_copy = (
        list(raw_first)
        if isinstance(raw_first, (list, tuple))
        or (not isinstance(raw_first, (str, bytes, dict)) and hasattr(raw_first, "__iter__"))
        else []
    )
    res = _orig_compute(*fwd_args, **fwd_kwargs)
    _invocations.append((vals_copy, res))
    return res


_calc_mod.compute_summary = _wrapped_compute
for _attr_name, _attr_val in list(vars(_cli_mod).items()):
    if _attr_val is _orig_compute:
        setattr(_cli_mod, _attr_name, _wrapped_compute)

sig = inspect.signature(main)
positional = [
    p for p in sig.parameters.values()
    if p.kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.VAR_POSITIONAL,
    )
]
kw_only_argv = (
    not positional
    and "argv" in sig.parameters
    and sig.parameters["argv"].kind == inspect.Parameter.KEYWORD_ONLY
)

if positional or kw_only_argv:
    for argv_vals, float_vals in ((["2", "4", "6"], [2.0, 4.0, 6.0]), (["3", "5"], [3.0, 5.0])):
        buf = io.StringIO()
        before_idx = len(_invocations)
        with contextlib.redirect_stdout(buf):
            ret = main(argv_vals) if positional else main(argv=argv_vals)
        recent = _invocations[before_idx:]
        if not recent:
            raise AssertionError(
                f"cli.main({argv_vals!r}) did not invoke compute_summary at runtime"
            )
        label = f"cli.main({argv_vals!r})"
        payload = _extract_cli_payload(buf.getvalue().strip(), ret, label)
        _check_summary_payload(payload, float_vals, label)
        matching_calls = [
            (inv_vals, inv_ret)
            for inv_vals, inv_ret in recent
            if _vals_match(inv_vals, float_vals) and _payloads_match(payload, inv_ret)
        ]
        if not matching_calls:
            raise AssertionError(
                f"{label} did not pass actual inputs {float_vals!r} to compute_summary "
                f"and return/emit its result (observed calls={recent!r}, payload={payload!r})"
            )
else:
    def _run_zero_arg(argv_override, label):
        buf = io.StringIO()
        before_idx = len(_invocations)
        orig_argv = list(sys.argv)
        try:
            sys.argv = argv_override
            with contextlib.redirect_stdout(buf):
                ret = main()
        finally:
            sys.argv = orig_argv
        recent = _invocations[before_idx:]
        if not recent:
            raise AssertionError(f"{label} did not invoke compute_summary at runtime")
        payload = _extract_cli_payload(buf.getvalue().strip(), ret, label)
        matched_inv = None
        for inv_vals, inv_ret in recent:
            if not inv_vals:
                continue
            try:
                f_vals = [float(x) for x in inv_vals]
            except (TypeError, ValueError):
                continue
            if _payloads_match(payload, inv_ret):
                _check_summary_payload(payload, f_vals, label)
                matched_inv = f_vals
                break
        if matched_inv is None:
            raise AssertionError(
                f"{label} output did not match any compute_summary call "
                f"(calls={recent!r}, payload={payload!r})"
            )
        return matched_inv

    _cli_src_file = getattr(_cli_mod, "__file__", None)
    _has_main_guard = False
    if _cli_src_file:
        with open(_cli_src_file, "r", encoding="utf-8", errors="replace") as _fh:
            _cli_tree = _ast.parse(_fh.read())
        for _node in _ast.walk(_cli_tree):
            if isinstance(_node, _ast.If) and isinstance(_node.test, _ast.Compare):
                _names = [
                    n.id
                    for n in _ast.walk(_node.test)
                    if isinstance(n, _ast.Name) and n.id == "__name__"
                ]
                _consts = [
                    c.value
                    for c in _ast.walk(_node.test)
                    if isinstance(c, _ast.Constant) and c.value == "__main__"
                ]
                if _names and _consts:
                    _has_main_guard = True
                    break

    first_vals = _run_zero_arg(["src_pkg.cli", "2", "4", "6"], "cli.main()")
    if _has_main_guard and not _vals_match(first_vals, [2.0, 4.0, 6.0]):
        raise AssertionError(
            "cli.main() with __main__ guard did not forward sys.argv [2, 4, 6] "
            f"to compute_summary: {first_vals!r}"
        )
    if _has_main_guard or _vals_match(first_vals, [2.0, 4.0, 6.0]):
        second_vals = _run_zero_arg(["src_pkg.cli", "3", "5"], "cli.main()[3,5]")
        if not _vals_match(second_vals, [3.0, 5.0]):
            raise AssertionError(
                f"cli.main() did not forward second sys.argv [3, 5] to compute_summary: "
                f"{second_vals!r}"
            )

if getattr(_cli_mod, "__file__", None):
    with open(_cli_mod.__file__, "r", encoding="utf-8", errors="replace") as _fh:
        _cli_tree2 = _ast.parse(_fh.read())
    _guard_present = any(
        isinstance(_n, _ast.If)
        and isinstance(_n.test, _ast.Compare)
        and any(isinstance(_x, _ast.Name) and _x.id == "__name__" for _x in _ast.walk(_n.test))
        and any(
            isinstance(_x, _ast.Constant) and _x.value == "__main__"
            for _x in _ast.walk(_n.test)
        )
        for _n in _ast.walk(_cli_tree2)
    )
    if _guard_present:
        for _argv_vals, _float_vals in (
            (["2", "4", "6"], [2.0, 4.0, 6.0]),
            (["3", "5"], [3.0, 5.0]),
        ):
            _buf = io.StringIO()
            _before = len(_invocations)
            _orig_argv = list(sys.argv)
            _saved_cli_mod = sys.modules.pop("src_pkg.cli", None)
            try:
                sys.argv = ["src_pkg.cli", *_argv_vals]
                with _warnings.catch_warnings():
                    _warnings.simplefilter("ignore", RuntimeWarning)
                    with contextlib.redirect_stdout(_buf):
                        try:
                            _runpy.run_module("src_pkg.cli", run_name="__main__")
                        except SystemExit as _sys_exc:
                            if _sys_exc.code not in (0, None):
                                raise AssertionError(
                                    f"src_pkg.cli __main__ exited with code {_sys_exc.code!r}"
                                )
            finally:
                sys.argv = _orig_argv
                if _saved_cli_mod is not None:
                    sys.modules["src_pkg.cli"] = _saved_cli_mod
            _recent = _invocations[_before:]
            if not _recent:
                raise AssertionError(
                    f"python -m src_pkg.cli {_argv_vals!r} did not invoke "
                    "compute_summary at runtime"
                )
            _out_txt = _buf.getvalue().strip()
            if not _out_txt:
                raise AssertionError(
                    f"python -m src_pkg.cli {_argv_vals!r} produced empty stdout"
                )
            _payload = _extract_cli_payload(_out_txt, 0, f"__main__({_argv_vals!r})")
            _check_summary_payload(_payload, _float_vals, f"__main__({_argv_vals!r})")
            if not any(
                _vals_match(_iv, _float_vals) and _payloads_match(_payload, _ir)
                for _iv, _ir in _recent
            ):
                raise AssertionError(
                    f"__main__({_argv_vals!r}) bypassed compute_summary or altered its result "
                    f"(calls={_recent!r}, payload={_payload!r})"
                )
"""


def _cli_has_main_guard(source_text: str) -> bool:
    """Return True if module defines an `if __name__ == '__main__':` entrypoint."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if isinstance(test, ast.Compare):
                names = [
                    n.id for n in ast.walk(test) if isinstance(n, ast.Name) and n.id == "__name__"
                ]
                consts = [
                    c.value
                    for c in ast.walk(test)
                    if isinstance(c, ast.Constant) and c.value == "__main__"
                ]
                if names and consts:
                    return True
    return False


def _validate_cli_json_payload(payload: object, expected_vals: Sequence[float]) -> str | None:
    if not isinstance(payload, dict) or "sum" not in payload:
        return f"unexpected JSON payload (missing sum): {payload!r}"
    exp_sum = sum(expected_vals)
    exp_count = float(len(expected_vals))
    exp_mean = exp_sum / exp_count
    exp_min = min(expected_vals)
    exp_max = max(expected_vals)
    try:
        if abs(float(payload["sum"]) - exp_sum) > 1e-6:
            return f"sum mismatch (expected {exp_sum}): {payload!r}"
        if "count" in payload and abs(float(payload["count"]) - exp_count) > 1e-6:
            return f"count mismatch (expected {exp_count}): {payload!r}"
        for avg_key in ("mean", "avg"):
            if avg_key in payload and abs(float(payload[avg_key]) - exp_mean) > 1e-6:
                return f"{avg_key} mismatch (expected {exp_mean}): {payload!r}"
        if "min" in payload and abs(float(payload["min"]) - exp_min) > 1e-6:
            return f"min mismatch (expected {exp_min}): {payload!r}"
        if "max" in payload and abs(float(payload["max"]) - exp_max) > 1e-6:
            return f"max mismatch (expected {exp_max}): {payload!r}"
    except (TypeError, ValueError) as exc:
        return f"non-numeric summary field ({exc}): {payload!r}"
    return None


def deliverable_has_ast_symbols(
    source_text: str,
    required_symbols: Sequence[str],
    *,
    deliverable_id: str = "",
) -> tuple[bool, list[str]]:
    """Verify via Python AST that required functions/classes/calls are genuinely defined."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return False, list(required_symbols)

    defined: set[str] = set()
    top_level_test_defs: set[str] = set()
    imported: set[str] = set()
    imported_modules: set[str] = set()
    relative_imported_modules: set[str] = set()
    import_aliases: dict[str, str] = {}
    called: set[str] = set()

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            top_level_test_defs.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef) and stmt.name.startswith("Test"):
            for member in stmt.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    top_level_test_defs.add(member.name)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.ImportFrom):
            mod_prefix = node.module or ""
            for alias in node.names:
                local_name = alias.asname or alias.name
                imported.add(local_name)
                import_aliases[local_name] = alias.name
                full_mod = f"{mod_prefix}.{alias.name}" if mod_prefix else alias.name
                imported_modules.add(full_mod)
                if node.level > 0:
                    relative_imported_modules.add(full_mod)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                imported.add(local_name)
                imported_modules.add(alias.name)
                import_aliases[local_name] = alias.name
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
                if func.id in import_aliases:
                    called.add(import_aliases[func.id])
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)

    missing: list[str] = []
    did = deliverable_id.upper()
    for sym in required_symbols:
        if did == "D2" and sym == "compute_summary":
            has_direct_calc_import = (
                f"src_pkg.calc.{sym}" in imported_modules
                or f"calc.{sym}" in relative_imported_modules
            )
            has_calc_module = (
                "src_pkg.calc" in imported_modules
                or "src_pkg" in imported_modules
                or "src_pkg" in imported
                or "calc" in imported
                or "calc" in relative_imported_modules
            )
            has_import = has_direct_calc_import or (has_calc_module and sym in called)
            if not (has_import and sym in called):
                missing.append(sym)
        elif did == "D3":
            if sym not in top_level_test_defs:
                missing.append(sym)
        elif did in {"D1", "D2"}:
            if sym not in defined:
                missing.append(sym)
        else:
            if sym not in defined and sym not in imported:
                missing.append(sym)

    return len(missing) == 0, missing


def _check_d3_non_vacuous(proj_dir: Path, *, timeout_s: float = 30.0) -> tuple[bool, str]:
    """Verify D3 test_summary_cli_roundtrip fails when src_pkg or cli.py alone is mutated."""
    with tempfile.TemporaryDirectory(prefix="cb10_mut_") as tmp_dir:
        mut_dir = Path(tmp_dir) / "proj"
        shutil.copytree(proj_dir, mut_dir)
        calc_path = mut_dir / "src_pkg" / "calc.py"
        cli_path = mut_dir / "src_pkg" / "cli.py"
        if not calc_path.is_file() or not cli_path.is_file():
            return False, "Missing src_pkg/calc.py or src_pkg/cli.py for D3 mutation check."
        calc_path.write_text(
            "def compute_summary(*_args, **_kwargs):\n"
            "    return {'count': -1.0, 'sum': -999999.0, 'min': -999999.0, "
            "'max': -999999.0, 'mean': -999999.0, 'avg': -999999.0}\n",
            encoding="utf-8",
        )
        cli_path.write_text(
            "import json\n"
            "from src_pkg.calc import compute_summary\n"
            "def main(*_args, **_kwargs):\n"
            "    print(json.dumps(compute_summary([])))\n"
            "    return 1\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )
        mut_proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-k", "test_summary_cli_roundtrip"],
            cwd=str(mut_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if mut_proc.returncode == 0:
            return (
                False,
                "D3 test_summary_cli_roundtrip is vacuous (passed even with mutated src_pkg).",
            )
        if mut_proc.returncode == 5:
            return (
                False,
                "D3 test_summary_cli_roundtrip was not collected by pytest (exit code 5).",
            )
        if mut_proc.returncode != 1:
            return (
                False,
                "D3 mutation check did not produce a test failure "
                f"(pytest rc={mut_proc.returncode}).",
            )

        mut_cli_dir = Path(tmp_dir) / "proj_cli_only"
        shutil.copytree(proj_dir, mut_cli_dir)
        (mut_cli_dir / "src_pkg" / "cli.py").write_text(
            "import json\n"
            "from src_pkg.calc import compute_summary\n"
            "def main(*_args, **_kwargs):\n"
            "    print(json.dumps({'count': -1.0, 'sum': -999999.0, 'min': -999999.0, "
            "'max': -999999.0, 'mean': -999999.0, 'avg': -999999.0}))\n"
            "    return 1\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )
        mut_cli_proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-k", "test_summary_cli_roundtrip"],
            cwd=str(mut_cli_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if mut_cli_proc.returncode == 0:
            return (
                False,
                "D3 test_summary_cli_roundtrip skips src_pkg.cli "
                "(passed even with broken src_pkg/cli.py).",
            )
        if mut_cli_proc.returncode == 5:
            return (
                False,
                "D3 test_summary_cli_roundtrip was not collected by pytest on CLI mutation "
                "(exit code 5).",
            )
        if mut_cli_proc.returncode != 1:
            return (
                False,
                "D3 CLI mutation check did not produce a test failure "
                f"(pytest rc={mut_cli_proc.returncode}).",
            )
    return True, ""


def evaluate_cb10_project(
    proj_dir: Path,
    spec: CB10ProjectSpec | None = None,
    *,
    timeout_s: float = 30.0,
) -> tuple[bool, dict[str, bool], str]:
    """Independently verify AST symbols, compileall build, pytest, and CLI/calc execution."""
    resolved_spec = spec or build_cb10_three_deliverables_spec()
    assertions: dict[str, bool] = {
        "project_dir_exists": proj_dir.is_dir(),
    }
    errors: list[str] = []

    if not proj_dir.is_dir():
        return False, assertions, f"CB-10 project directory missing: {proj_dir}"

    for deliverable in resolved_spec.deliverables:
        target = proj_dir / deliverable.rel_path
        exists_key = f"{deliverable.deliverable_id.lower()}_exists"
        syms_key = f"{deliverable.deliverable_id.lower()}_symbols"
        exists = target.is_file()
        assertions[exists_key] = exists
        if not exists:
            assertions[syms_key] = False
            errors.append(f"Missing {deliverable.deliverable_id} ({deliverable.rel_path})")
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        has_syms, missing = deliverable_has_ast_symbols(
            text,
            deliverable.required_symbols,
            deliverable_id=deliverable.deliverable_id,
        )
        assertions[syms_key] = has_syms
        if not has_syms:
            errors.append(
                f"{deliverable.deliverable_id} ({deliverable.rel_path}) missing AST symbols "
                f"{missing}"
            )

    build_cmd = list(resolved_spec.build_command)
    if "compileall" in build_cmd and "-f" not in build_cmd:
        build_cmd.insert(build_cmd.index("compileall") + 1, "-f")
    try:
        build_proc = subprocess.run(
            build_cmd,
            cwd=str(proj_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        build_ok = build_proc.returncode == 0
        if not build_ok:
            errors.append(
                f"Build failed (rc={build_proc.returncode}): "
                f"{(build_proc.stderr or build_proc.stdout).strip()[:240]}"
            )
    except (OSError, subprocess.SubprocessError) as exc:
        build_ok = False
        errors.append(f"Build execution error: {exc}")
    assertions["build_passed"] = build_ok

    try:
        test_proc = subprocess.run(
            list(resolved_spec.test_command),
            cwd=str(proj_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        test_ok = test_proc.returncode == 0
        if not test_ok:
            errors.append(
                f"Tests failed (rc={test_proc.returncode}): "
                f"{(test_proc.stdout + ' ' + test_proc.stderr).strip()[:240]}"
            )
    except (OSError, subprocess.SubprocessError) as exc:
        test_ok = False
        errors.append(f"Test execution error: {exc}")
    assertions["tests_passed"] = test_ok

    d3_non_vacuous = False
    if test_ok:
        try:
            d3_non_vacuous, d3_err = _check_d3_non_vacuous(proj_dir, timeout_s=timeout_s)
            if not d3_non_vacuous and d3_err:
                errors.append(d3_err)
        except (OSError, subprocess.SubprocessError) as exc:
            d3_non_vacuous = False
            errors.append(f"D3 mutation verification error: {exc}")
    assertions["d3_non_vacuous"] = d3_non_vacuous

    indep_ok = False
    cli_path = proj_dir / "src_pkg" / "cli.py"
    has_main_guard = (
        _cli_has_main_guard(cli_path.read_text(encoding="utf-8", errors="replace"))
        if cli_path.is_file()
        else False
    )
    try:
        mod_proc = subprocess.run(
            [sys.executable, "-m", "src_pkg.cli", "2", "4", "6"],
            cwd=str(proj_dir),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if mod_proc.returncode != 0:
            errors.append(
                f"python -m src_pkg.cli failed (rc={mod_proc.returncode}): "
                f"{(mod_proc.stderr or mod_proc.stdout).strip()[:240]}"
            )
        else:
            import json as _json

            mod_out = mod_proc.stdout.strip()
            mod_json_ok = True
            if has_main_guard and not mod_out:
                mod_json_ok = False
                errors.append(
                    "python -m src_pkg.cli produced empty stdout (expected JSON summary output)."
                )
            elif mod_out:
                for cli_args, expected_vals in (
                    (["2", "4", "6"], [2.0, 4.0, 6.0]),
                    (["3", "5"], [3.0, 5.0]),
                ):
                    run_proc = (
                        mod_proc
                        if cli_args == ["2", "4", "6"]
                        else subprocess.run(
                            [sys.executable, "-m", "src_pkg.cli", *cli_args],
                            cwd=str(proj_dir),
                            capture_output=True,
                            text=True,
                            timeout=timeout_s,
                            check=False,
                        )
                    )
                    if run_proc.returncode != 0:
                        mod_json_ok = False
                        errors.append(
                            f"python -m src_pkg.cli {' '.join(cli_args)} failed "
                            f"(rc={run_proc.returncode}): "
                            f"{(run_proc.stderr or run_proc.stdout).strip()[:240]}"
                        )
                        break
                    run_out = run_proc.stdout.strip()
                    if not run_out:
                        mod_json_ok = False
                        errors.append(
                            f"python -m src_pkg.cli {' '.join(cli_args)} produced empty stdout."
                        )
                        break
                    try:
                        try:
                            parsed_mod = _json.loads(run_out)
                        except _json.JSONDecodeError:
                            parsed_mod = _json.loads(run_out.splitlines()[-1])
                    except (ValueError, TypeError) as exc:
                        mod_json_ok = False
                        errors.append(
                            f"python -m src_pkg.cli invalid JSON output ({exc}): {run_out[:180]}"
                        )
                        break
                    mismatch = _validate_cli_json_payload(parsed_mod, expected_vals)
                    if mismatch is not None:
                        mod_json_ok = False
                        errors.append(f"python -m src_pkg.cli {mismatch}")
                        break

            if mod_json_ok:
                verify_proc = subprocess.run(
                    [sys.executable, "-c", _INDEPENDENT_VERIFY_SCRIPT],
                    cwd=str(proj_dir),
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                )
                if verify_proc.returncode == 0:
                    indep_ok = True
                else:
                    detail_err = (verify_proc.stderr or verify_proc.stdout).strip()[:240]
                    errors.append(
                        f"Independent compute_summary/cli check failed "
                        f"(rc={verify_proc.returncode}): {detail_err}"
                    )
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(f"Independent CLI execution error: {exc}")
    assertions["independent_cli_passed"] = indep_ok

    passed = all(assertions.values())
    detail = (
        f"Verified all {len(resolved_spec.deliverables)} deliverables, "
        "AST symbols, compileall build, pytest, and independent CLI execution."
        if passed
        else "; ".join(errors)
    )
    return passed, assertions, detail


__all__ = [
    "CB10DeliverableSpec",
    "CB10ProjectSpec",
    "build_cb10_three_deliverables_spec",
    "deliverable_has_ast_symbols",
    "evaluate_cb10_project",
]
