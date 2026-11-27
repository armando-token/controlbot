"""Deterministic SpreadsheetVerifier with LibreOffice recalc + OOXML evaluator (CB-09)."""

from __future__ import annotations

import math
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from src.adapters.office_excel import (
    ParsedExcelCell,
    ParsedExcelSheet,
    format_cell_coord,
    infer_currency_from_value,
    parse_cell_coord,
    read_workbook_ooxml,
)
from src.contracts.common import FrozenModel
from src.contracts.envelope import VerdictState

EXCEL_ERROR_TOKENS: frozenset[str] = frozenset(
    {"#REF!", "#DIV/0!", "#VALUE!", "#NAME?", "#N/A", "#NUM!", "#NULL!"}
)

_RANGE_FUNCTIONS: frozenset[str] = frozenset(
    {"SUM", "SUMIF", "SUMIFS", "AVERAGE", "MIN", "MAX", "COUNT", "COUNTA"}
)
_NUMERIC_STR_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")


class ExcelFormulaEvalError(Exception):
    """Signals an Excel formula error token (#DIV/0!, #REF!, #VALUE!, #NAME?, etc.)."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class SpreadsheetVerificationReport(FrozenModel):
    """Audit report emitted by SpreadsheetVerifier."""

    passed: bool
    verdict: VerdictState
    formulas_total: int = Field(ge=0)
    formulas_ok: int = Field(ge=0)
    recalc_engine: Literal["libreoffice", "ooxml_evaluator"]
    badge: str
    errors: tuple[str, ...] = ()
    mixed_currencies_detected: bool = False
    mixed_currency_details: tuple[str, ...] = ()
    evaluated_values: dict[str, str | int | float] = Field(default_factory=dict)


def _split_top_level_args(arg_str: str) -> list[str]:
    args: list[str] = []
    depth = 0
    in_quotes = False
    buf: list[str] = []
    for ch in arg_str:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif not in_quotes:
            if ch == "(":
                depth += 1
                buf.append(ch)
            elif ch == ")":
                depth -= 1
                buf.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(buf).strip())
                buf.clear()
            else:
                buf.append(ch)
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail or args:
        args.append(tail)
    return args


def _strip_sheet_prefix(ref: str, default_sheet: str) -> tuple[str, str]:
    if "!" in ref:
        sheet_part, coord_part = ref.rsplit("!", 1)
        cleaned_sheet = sheet_part.strip()
        if (
            len(cleaned_sheet) >= 2
            and cleaned_sheet.startswith("'")
            and cleaned_sheet.endswith("'")
        ):
            cleaned_sheet = cleaned_sheet[1:-1].replace("''", "'")
        return cleaned_sheet, coord_part.strip()
    return default_sheet, ref.strip()


_SHEET_PREFIX_RE = r"(?:(?:'(?:[^']|'')+'|[A-Za-z0-9_]+)!)"
_CELL_COORD_RE = r"\$?[A-Za-z]{1,3}\$?\d+"
_RANGE_SPLIT_RE = re.compile(
    rf"^({_SHEET_PREFIX_RE}?{_CELL_COORD_RE}):({_SHEET_PREFIX_RE}?{_CELL_COORD_RE})$"
)


def _expand_range_coords(
    range_expr: str,
    *,
    default_sheet: str,
    sheet_map: Mapping[str, ParsedExcelSheet],
) -> tuple[str, list[str]]:
    match = _RANGE_SPLIT_RE.fullmatch(range_expr.strip())
    if match is None:
        if ":" not in range_expr:
            raise ExcelFormulaEvalError("#REF!")
        left, right = range_expr.rsplit(":", 1)
    else:
        left, right = match.group(1), match.group(2)
    sheet_l, coord_l = _strip_sheet_prefix(left, default_sheet)
    sheet_r, coord_r = _strip_sheet_prefix(right, default_sheet)
    target_sheet = sheet_l
    if sheet_r != default_sheet and sheet_r != sheet_l:
        raise ExcelFormulaEvalError("#REF!")
    if target_sheet not in sheet_map:
        raise ExcelFormulaEvalError("#REF!")
    try:
        r1, c1 = parse_cell_coord(coord_l.replace("$", ""))
        r2, c2 = parse_cell_coord(coord_r.replace("$", ""))
    except ValueError as exc:
        raise ExcelFormulaEvalError("#REF!") from exc
    r_lo, r_hi = min(r1, r2), max(r1, r2)
    c_lo, c_hi = min(c1, c2), max(c1, c2)
    coords: list[str] = []
    for r in range(r_lo, r_hi + 1):
        for c in range(c_lo, c_hi + 1):
            coords.append(format_cell_coord(r, c))
    return target_sheet, coords


def _to_float(val: Any) -> float:
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)):
        if math.isnan(val) or math.isinf(val):
            raise ExcelFormulaEvalError("#NUM!")
        return float(val)
    if val is None:
        return 0.0
    if isinstance(val, str):
        s = val.strip()
        if s in EXCEL_ERROR_TOKENS:
            raise ExcelFormulaEvalError(s)
        if _NUMERIC_STR_RE.fullmatch(s):
            return float(s)
    raise ExcelFormulaEvalError("#VALUE!")


def _matches_criteria(cell_val: Any, criteria: Any) -> bool:
    if isinstance(criteria, str):
        crit = criteria.strip()
        for op in ("<>", ">=", "<=", "=", ">", "<"):
            if crit.startswith(op):
                rhs_raw = crit[len(op) :].strip()
                try:
                    lhs_num = _to_float(cell_val)
                    rhs_num = float(rhs_raw)
                    if op == "=":
                        return abs(lhs_num - rhs_num) < 1e-9
                    if op == "<>":
                        return abs(lhs_num - rhs_num) >= 1e-9
                    if op == ">":
                        return lhs_num > rhs_num
                    if op == ">=":
                        return lhs_num >= rhs_num
                    if op == "<":
                        return lhs_num < rhs_num
                    if op == "<=":
                        return lhs_num <= rhs_num
                except (ValueError, ExcelFormulaEvalError):
                    lhs_s = "" if cell_val is None else str(cell_val).strip().lower()
                    rhs_s = rhs_raw.lower()
                    if op == "=":
                        return lhs_s == rhs_s
                    if op == "<>":
                        return lhs_s != rhs_s
                    return False
        return str(cell_val or "").strip().lower() == crit.lower()
    if isinstance(criteria, (int, float)) and isinstance(cell_val, (int, float)):
        return abs(float(cell_val) - float(criteria)) < 1e-9
    return bool(cell_val == criteria)


class _FormulaEvaluator:
    """Pure-Python deterministic OOXML Excel formula evaluator."""

    def __init__(self, sheets: Sequence[ParsedExcelSheet]) -> None:
        self._sheets: dict[str, ParsedExcelSheet] = {s.name: s for s in sheets}
        self._cache: dict[tuple[str, str], Any] = {}
        self._visiting: set[tuple[str, str]] = set()
        self.range_refs_by_cell: dict[tuple[str, str], list[tuple[str, list[str]]]] = {}
        self.cell_refs_by_cell: dict[tuple[str, str], list[tuple[str, str]]] = {}

    def evaluate_cell(self, sheet_name: str, coord: str) -> Any:
        key = (sheet_name, coord.upper())
        if key in self._cache:
            return self._cache[key]
        if key in self._visiting:
            raise ExcelFormulaEvalError("#REF!")
        sheet = self._sheets.get(sheet_name)
        if sheet is None:
            raise ExcelFormulaEvalError("#REF!")
        cell: ParsedExcelCell | None = sheet.cells.get(coord.upper())
        if cell is None:
            return None
        if cell.formula is None:
            val = cell.value
            if isinstance(val, str) and val.strip() in EXCEL_ERROR_TOKENS:
                raise ExcelFormulaEvalError(val.strip())
            return val

        self._visiting.add(key)
        try:
            result = self._eval_expr(
                cell.formula, current_sheet=sheet_name, owner_coord=coord.upper()
            )
            self._cache[key] = result
            return result
        finally:
            self._visiting.discard(key)

    def _eval_expr(self, expr: str, *, current_sheet: str, owner_coord: str) -> Any:
        tokens = self._tokenize(expr)
        return self._eval_tokens(tokens, current_sheet=current_sheet, owner_coord=owner_coord)

    def _eval_tokens(
        self,
        tokens: list[tuple[str, str]],
        *,
        current_sheet: str,
        owner_coord: str,
    ) -> Any:
        pos = 0

        def _peek() -> tuple[str, str] | None:
            return tokens[pos] if pos < len(tokens) else None

        def _consume() -> tuple[str, str]:
            nonlocal pos
            tok = tokens[pos]
            pos += 1
            return tok

        def _parse_comparison() -> Any:
            left = _parse_add_sub()
            while (
                (nxt := _peek()) is not None
                and nxt[0] == "OP"
                and nxt[1]
                in {
                    "=",
                    "<>",
                    "<",
                    "<=",
                    ">",
                    ">=",
                }
            ):
                op = _consume()[1]
                right = _parse_add_sub()
                left_is_num = isinstance(left, (int, float)) and not isinstance(left, bool)
                right_is_num = isinstance(right, (int, float)) and not isinstance(right, bool)
                if (left_is_num and (right_is_num or right is None)) or (
                    left is None and right_is_num
                ):
                    lf = 0.0 if left is None else float(left)
                    rf = 0.0 if right is None else float(right)
                    if op == "=":
                        left = lf == rf
                    elif op == "<>":
                        left = lf != rf
                    elif op == "<":
                        left = lf < rf
                    elif op == "<=":
                        left = lf <= rf
                    elif op == ">":
                        left = lf > rf
                    elif op == ">=":
                        left = lf >= rf
                elif (isinstance(left, bool) and (isinstance(right, bool) or right is None)) or (
                    left is None and isinstance(right, bool)
                ):
                    lb = False if left is None else bool(left)
                    rb = False if right is None else bool(right)
                    if op == "=":
                        left = lb == rb
                    elif op == "<>":
                        left = lb != rb
                    else:
                        li, ri = (1 if lb else 0), (1 if rb else 0)
                        left = (
                            li < ri
                            if op == "<"
                            else (li <= ri if op == "<=" else (li > ri if op == ">" else li >= ri))
                        )
                else:
                    ls = "" if left is None else str(left)
                    rs = "" if right is None else str(right)
                    if op == "=":
                        left = ls == rs
                    elif op == "<>":
                        left = ls != rs
                    else:
                        left = (
                            ls < rs
                            if op == "<"
                            else (ls <= rs if op == "<=" else (ls > rs if op == ">" else ls >= rs))
                        )
            return left

        def _parse_add_sub() -> Any:
            left = _parse_mul_div()
            while (nxt := _peek()) is not None and nxt[0] == "OP" and nxt[1] in {"+", "-"}:
                op = _consume()[1]
                right = _parse_mul_div()
                lf = _to_float(left)
                rf = _to_float(right)
                left = lf + rf if op == "+" else lf - rf
            return left

        def _parse_mul_div() -> Any:
            left = _parse_unary()
            while (nxt := _peek()) is not None and nxt[0] == "OP" and nxt[1] in {"*", "/"}:
                op = _consume()[1]
                right = _parse_unary()
                lf = _to_float(left)
                rf = _to_float(right)
                if op == "/":
                    if rf == 0.0:
                        raise ExcelFormulaEvalError("#DIV/0!")
                    left = lf / rf
                else:
                    left = lf * rf
            return left

        def _parse_unary() -> Any:
            nxt = _peek()
            if nxt is not None and nxt[0] == "OP" and nxt[1] in {"+", "-"}:
                op = _consume()[1]
                val = _parse_unary()
                fval = _to_float(val)
                return -fval if op == "-" else fval
            return _parse_postfix()

        def _parse_postfix() -> Any:
            val = _parse_primary()
            while (nxt := _peek()) is not None and nxt[0] == "PCT":
                _consume()
                val = _to_float(val) / 100.0
            return val

        def _parse_primary() -> Any:
            tok = _peek()
            if tok is None:
                raise ExcelFormulaEvalError("#VALUE!")
            ttype, tval = tok
            if ttype == "LPAREN":
                _consume()
                val = _parse_comparison()
                closing = _peek()
                if closing is None or closing[0] != "RPAREN":
                    raise ExcelFormulaEvalError("#VALUE!")
                _consume()
                return val
            if ttype == "NUM":
                _consume()
                return float(tval) if "." in tval else int(tval)
            if ttype == "STR":
                _consume()
                return tval
            if ttype == "ERR":
                _consume()
                raise ExcelFormulaEvalError(tval)
            if ttype == "FUNC":
                fn_name = _consume()[1].upper()
                # Extract raw argument string inside balanced parens from token stream
                if _peek() is None or _peek() != ("LPAREN", "("):
                    raise ExcelFormulaEvalError("#NAME?")
                _consume()
                if fn_name == "IF":
                    arg_slices: list[list[tuple[str, str]]] = []
                    cur_slice: list[tuple[str, str]] = []
                    depth = 0
                    closed = False
                    while pos < len(tokens):
                        sub_tok = _consume()
                        st_type, _ = sub_tok
                        if st_type == "LPAREN":
                            depth += 1
                            cur_slice.append(sub_tok)
                        elif st_type == "RPAREN":
                            if depth == 0:
                                arg_slices.append(cur_slice)
                                closed = True
                                break
                            depth -= 1
                            cur_slice.append(sub_tok)
                        elif st_type == "COMMA" and depth == 0:
                            arg_slices.append(cur_slice)
                            cur_slice = []
                        else:
                            cur_slice.append(sub_tok)
                    if (
                        not closed
                        or len(arg_slices) < 2
                        or len(arg_slices) > 3
                        or any(not sl for sl in arg_slices)
                    ):
                        raise ExcelFormulaEvalError("#VALUE!")
                    cond_val = self._eval_tokens(
                        arg_slices[0], current_sheet=current_sheet, owner_coord=owner_coord
                    )
                    if bool(cond_val):
                        return self._eval_tokens(
                            arg_slices[1], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    if len(arg_slices) >= 3:
                        return self._eval_tokens(
                            arg_slices[2], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    return False

                arg_vals: list[Any] = []
                raw_ranges: list[str] = []
                if _peek() != ("RPAREN", ")"):
                    while True:
                        # Check if next slice up to comma/rparen is a direct range ref
                        if (
                            _peek() is not None and _peek()[0] == "RANGE"  # type: ignore[index]
                        ):
                            r_tok = _consume()[1]
                            raw_ranges.append(r_tok)
                            arg_vals.append(("__RANGE__", r_tok))
                        else:
                            arg_vals.append(_parse_comparison())
                        nxt = _peek()
                        if nxt is not None and nxt[0] == "COMMA":
                            _consume()
                            continue
                        if nxt is not None and nxt[0] == "RPAREN":
                            break
                        raise ExcelFormulaEvalError("#VALUE!")
                _consume()  # consume ')'
                return self._eval_function(
                    fn_name,
                    arg_vals,
                    raw_ranges=raw_ranges,
                    current_sheet=current_sheet,
                    owner_coord=owner_coord,
                )
            if ttype == "REF":
                _consume()
                target_sheet, coord_part = _strip_sheet_prefix(tval, current_sheet)
                clean_coord = coord_part.replace("$", "").upper()
                try:
                    parse_cell_coord(clean_coord)
                except ValueError as exc:
                    raise ExcelFormulaEvalError("#REF!") from exc
                self.cell_refs_by_cell.setdefault((current_sheet, owner_coord), []).append(
                    (target_sheet, clean_coord)
                )
                return self.evaluate_cell(target_sheet, clean_coord)
            if ttype == "IDENT":
                _consume()
                upper_id = tval.upper()
                if upper_id == "TRUE":
                    return True
                if upper_id == "FALSE":
                    return False
                raise ExcelFormulaEvalError("#NAME?")
            raise ExcelFormulaEvalError("#VALUE!")

        val = _parse_comparison()
        if pos != len(tokens):
            raise ExcelFormulaEvalError("#VALUE!")
        return val

    def _resolve_range_values(
        self,
        range_expr: str,
        *,
        current_sheet: str,
        owner_coord: str,
        numeric_only: bool = True,
    ) -> list[Any]:
        target_sheet, coords = _expand_range_coords(
            range_expr, default_sheet=current_sheet, sheet_map=self._sheets
        )
        self.range_refs_by_cell.setdefault((current_sheet, owner_coord), []).append(
            (target_sheet, coords)
        )
        vals: list[Any] = []
        for c in coords:
            v = self.evaluate_cell(target_sheet, c)
            if numeric_only:
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    vals.append(float(v))
                elif isinstance(v, str) and v.strip() in EXCEL_ERROR_TOKENS:
                    raise ExcelFormulaEvalError(v.strip())
            else:
                vals.append(v)
        return vals

    def _eval_function(
        self,
        fn_name: str,
        args: list[Any],
        *,
        raw_ranges: list[str],
        current_sheet: str,
        owner_coord: str,
    ) -> Any:
        del raw_ranges
        if fn_name == "SUM":
            total = 0.0
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "__RANGE__":
                    total += sum(
                        self._resolve_range_values(
                            arg[1], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    )
                else:
                    total += _to_float(arg)
            return total

        if fn_name == "AVERAGE":
            nums: list[float] = []
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "__RANGE__":
                    nums.extend(
                        self._resolve_range_values(
                            arg[1], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    )
                else:
                    nums.append(_to_float(arg))
            if not nums:
                raise ExcelFormulaEvalError("#DIV/0!")
            return sum(nums) / len(nums)

        if fn_name in {"MIN", "MAX"}:
            nums = []
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "__RANGE__":
                    nums.extend(
                        self._resolve_range_values(
                            arg[1], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    )
                else:
                    nums.append(_to_float(arg))
            if not nums:
                return 0.0
            return min(nums) if fn_name == "MIN" else max(nums)

        if fn_name == "COUNT":
            cnt = 0
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "__RANGE__":
                    cnt += len(
                        self._resolve_range_values(
                            arg[1], current_sheet=current_sheet, owner_coord=owner_coord
                        )
                    )
                elif isinstance(arg, (int, float)) and not isinstance(arg, bool):
                    cnt += 1
            return cnt

        if fn_name == "COUNTA":
            cnt = 0
            for arg in args:
                if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "__RANGE__":
                    vals = self._resolve_range_values(
                        arg[1],
                        current_sheet=current_sheet,
                        owner_coord=owner_coord,
                        numeric_only=False,
                    )
                    cnt += sum(1 for v in vals if v is not None and str(v) != "")
                elif arg is not None and str(arg) != "":
                    cnt += 1
            return cnt

        if fn_name == "SUMIF":
            if len(args) < 2:
                raise ExcelFormulaEvalError("#VALUE!")
            crit_arg = args[0]
            criteria = args[1]
            sum_arg = args[2] if len(args) >= 3 else crit_arg
            if not (isinstance(crit_arg, tuple) and crit_arg[0] == "__RANGE__") or not (
                isinstance(sum_arg, tuple) and sum_arg[0] == "__RANGE__"
            ):
                raise ExcelFormulaEvalError("#VALUE!")
            crit_vals = self._resolve_range_values(
                crit_arg[1],
                current_sheet=current_sheet,
                owner_coord=owner_coord,
                numeric_only=False,
            )
            sum_vals = self._resolve_range_values(
                sum_arg[1],
                current_sheet=current_sheet,
                owner_coord=owner_coord,
                numeric_only=False,
            )
            total = 0.0
            for cv, sv in zip(crit_vals, sum_vals, strict=False):
                if (
                    _matches_criteria(cv, criteria)
                    and isinstance(sv, (int, float))
                    and not isinstance(sv, bool)
                ):
                    total += float(sv)
            return total

        if fn_name == "SUMIFS":
            if len(args) < 3 or len(args) % 2 == 0:
                raise ExcelFormulaEvalError("#VALUE!")
            sum_arg = args[0]
            if not (isinstance(sum_arg, tuple) and sum_arg[0] == "__RANGE__"):
                raise ExcelFormulaEvalError("#VALUE!")
            sum_vals = self._resolve_range_values(
                sum_arg[1],
                current_sheet=current_sheet,
                owner_coord=owner_coord,
                numeric_only=False,
            )
            pair_lists: list[tuple[list[Any], Any]] = []
            for idx in range(1, len(args), 2):
                c_range = args[idx]
                c_val = args[idx + 1]
                if not (isinstance(c_range, tuple) and c_range[0] == "__RANGE__"):
                    raise ExcelFormulaEvalError("#VALUE!")
                c_vals = self._resolve_range_values(
                    c_range[1],
                    current_sheet=current_sheet,
                    owner_coord=owner_coord,
                    numeric_only=False,
                )
                pair_lists.append((c_vals, c_val))
            total = 0.0
            for row_i, sv in enumerate(sum_vals):
                if (
                    all(
                        row_i < len(c_vals) and _matches_criteria(c_vals[row_i], c_target)
                        for c_vals, c_target in pair_lists
                    )
                    and isinstance(sv, (int, float))
                    and not isinstance(sv, bool)
                ):
                    total += float(sv)
            return total

        if fn_name == "IF":
            if len(args) < 2:
                raise ExcelFormulaEvalError("#VALUE!")
            cond = bool(args[0])
            if cond:
                return args[1]
            return args[2] if len(args) >= 3 else False

        if fn_name == "ROUND":
            if len(args) != 2:
                raise ExcelFormulaEvalError("#VALUE!")
            return round(_to_float(args[0]), int(_to_float(args[1])))

        if fn_name == "ABS":
            if len(args) != 1:
                raise ExcelFormulaEvalError("#VALUE!")
            return abs(_to_float(args[0]))

        raise ExcelFormulaEvalError("#NAME?")

    @staticmethod
    def _tokenize(expr: str) -> list[tuple[str, str]]:
        tokens: list[tuple[str, str]] = []
        i = 0
        n = len(expr)
        while i < n:
            ch = expr[i]
            if ch.isspace():
                i += 1
                continue
            if ch == "(":
                tokens.append(("LPAREN", "("))
                i += 1
                continue
            if ch == ")":
                tokens.append(("RPAREN", ")"))
                i += 1
                continue
            if ch == ",":
                tokens.append(("COMMA", ","))
                i += 1
                continue
            if expr[i : i + 2] in {"<>", "<=", ">="}:
                tokens.append(("OP", expr[i : i + 2]))
                i += 2
                continue
            if ch in {"+", "-", "*", "/", "=", "<", ">"}:
                tokens.append(("OP", ch))
                i += 1
                continue
            if ch == '"':
                j = i + 1
                buf: list[str] = []
                while j < n:
                    if expr[j] == '"':
                        if j + 1 < n and expr[j + 1] == '"':
                            buf.append('"')
                            j += 2
                            continue
                        break
                    buf.append(expr[j])
                    j += 1
                if j >= n:
                    raise ExcelFormulaEvalError("#VALUE!")
                tokens.append(("STR", "".join(buf)))
                i = j + 1
                continue
            if ch == "#":
                m_err = re.match(r"#[A-Z0-9/!?]+", expr[i:], re.IGNORECASE)
                if m_err:
                    tokens.append(("ERR", m_err.group(0).upper()))
                    i += len(m_err.group(0))
                    continue
                raise ExcelFormulaEvalError("#VALUE!")
            if ch.isdigit() or (ch == "." and i + 1 < n and expr[i + 1].isdigit()):
                m_num = re.match(r"\d+(?:\.\d+)?", expr[i:])
                assert m_num is not None
                tokens.append(("NUM", m_num.group(0)))
                i += len(m_num.group(0))
                continue

            if ch == "%":
                tokens.append(("PCT", "%"))
                i += 1
                continue

            # Range or cell reference (with optional Sheet! prefix) or function/ident
            m_range = re.match(
                rf"{_SHEET_PREFIX_RE}?{_CELL_COORD_RE}:{_SHEET_PREFIX_RE}?{_CELL_COORD_RE}",
                expr[i:],
            )
            if m_range:
                tokens.append(("RANGE", m_range.group(0)))
                i += len(m_range.group(0))
                continue

            m_ref = re.match(rf"{_SHEET_PREFIX_RE}?{_CELL_COORD_RE}", expr[i:])
            if m_ref:
                # Ensure it isn't immediately followed by '(' (which would be invalid)
                end_pos = i + len(m_ref.group(0))
                if end_pos < n and expr[end_pos] == "(":
                    tokens.append(("FUNC", m_ref.group(0)))
                else:
                    tokens.append(("REF", m_ref.group(0)))
                i = end_pos
                continue

            m_ident = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", expr[i:])
            if m_ident:
                name = m_ident.group(0)
                end_pos = i + len(name)
                if end_pos < n and expr[end_pos] == "(":
                    tokens.append(("FUNC", name))
                else:
                    tokens.append(("IDENT", name))
                i = end_pos
                continue

            raise ExcelFormulaEvalError("#VALUE!")
        return tokens


class SpreadsheetVerifier:
    """Verifies OOXML workbooks using LibreOffice recalculation or deterministic OOXML eval."""

    @staticmethod
    def find_libreoffice() -> str | None:
        return shutil.which("soffice") or shutil.which("libreoffice")

    def verify(
        self,
        path: Path,
        *,
        expected_totals: Mapping[str, float] | None = None,
        tolerance: float = 1e-6,
        force_ooxml_evaluator: bool = False,
    ) -> SpreadsheetVerificationReport:
        soffice_bin = None if force_ooxml_evaluator else self.find_libreoffice()
        recalc_engine: Literal["libreoffice", "ooxml_evaluator"] = "ooxml_evaluator"
        sheets: list[ParsedExcelSheet]

        if soffice_bin is not None:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_dir_path = Path(tmpdir)
                src_copy = tmp_dir_path / path.name
                shutil.copy2(path, src_copy)
                out_dir = tmp_dir_path / "out"
                out_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [
                        soffice_bin,
                        "--headless",
                        "--convert-to",
                        "xlsx",
                        "--outdir",
                        str(out_dir),
                        str(src_copy),
                    ],
                    check=True,
                    timeout=30,
                    capture_output=True,
                )
                recalc_path = out_dir / path.name
                sheets = read_workbook_ooxml(recalc_path if recalc_path.is_file() else path)
                recalc_engine = "libreoffice"
        else:
            sheets = read_workbook_ooxml(path)

        evaluator = _FormulaEvaluator(sheets)
        errors: list[str] = []
        evaluated_values: dict[str, str | int | float] = {}
        formulas_total = 0
        formulas_ok = 0

        # 1. Scan literal cells for any embedded Excel error tokens
        for sheet in sheets:
            for coord, cell in sorted(sheet.cells.items()):
                full_ref = f"{sheet.name}!{coord}"
                if cell.formula is None:
                    if isinstance(cell.value, str) and cell.value.strip() in EXCEL_ERROR_TOKENS:
                        errors.append(f"Literal error token in {full_ref}: {cell.value.strip()}")
                    continue

                formulas_total += 1
                # Check cached error token from LibreOffice or prior save
                if (
                    isinstance(cell.cached_value, str)
                    and cell.cached_value.strip() in EXCEL_ERROR_TOKENS
                ):
                    errors.append(f"Formula error in {full_ref}: {cell.cached_value.strip()}")
                    evaluated_values[full_ref] = cell.cached_value.strip()
                    continue

                try:
                    eval_res = evaluator.evaluate_cell(sheet.name, coord)
                except ExcelFormulaEvalError as exc:
                    errors.append(f"Formula error in {full_ref}: {exc.token}")
                    evaluated_values[full_ref] = exc.token
                    continue

                if isinstance(eval_res, str) and eval_res.strip() in EXCEL_ERROR_TOKENS:
                    errors.append(f"Formula error in {full_ref}: {eval_res.strip()}")
                    evaluated_values[full_ref] = eval_res.strip()
                    continue

                if isinstance(eval_res, (int, float)) and not isinstance(eval_res, bool):
                    evaluated_values[full_ref] = eval_res
                    if (
                        isinstance(cell.cached_value, (int, float))
                        and not isinstance(cell.cached_value, bool)
                        and abs(float(cell.cached_value) - float(eval_res)) > tolerance
                    ):
                        errors.append(
                            f"Numerical imbalance in {full_ref}: "
                            f"cached={cell.cached_value} != evaluated={eval_res}"
                        )
                        continue
                elif eval_res is not None:
                    evaluated_values[full_ref] = str(eval_res)

                formulas_ok += 1

        # 2. Check expected totals if provided
        if expected_totals:
            for ref_key, expected_val in expected_totals.items():
                if "!" in ref_key:
                    sh_part, coord_part = _strip_sheet_prefix(ref_key, sheets[0].name)
                    lookup_key = f"{sh_part}!{coord_part.upper()}"
                else:
                    lookup_key = f"{sheets[0].name}!{ref_key.upper()}"
                actual_val = evaluated_values.get(lookup_key)
                if actual_val is None and "!" not in ref_key:
                    # Fallback lookup across sheets
                    for s in sheets:
                        cand = f"{s.name}!{ref_key.upper()}"
                        if cand in evaluated_values:
                            actual_val = evaluated_values[cand]
                            lookup_key = cand
                            break
                if not isinstance(actual_val, (int, float)):
                    errors.append(
                        f"Expected total {lookup_key} missing or non-numeric ({actual_val!r})."
                    )
                elif abs(float(actual_val) - float(expected_val)) > tolerance:
                    errors.append(
                        f"Expected total mismatch at {lookup_key}: "
                        f"got {actual_val}, expected {expected_val}."
                    )

        # 3. Detect mixed currencies in formula ranges, direct cell refs, AND numeric columns
        mixed_details: list[str] = []
        sheet_map = {s.name: s for s in sheets}
        flagged_owners: set[tuple[str, str]] = set()

        def _cell_currencies(
            target_sheet: str,
            coord: str,
            visited: set[tuple[str, str]],
        ) -> set[str]:
            key = (target_sheet, coord)
            if key in visited:
                return set()
            visited.add(key)
            sh = sheet_map.get(target_sheet)
            if sh is None:
                return set()
            cell_obj = sh.cells.get(coord)
            if cell_obj is None:
                return set()
            curr = (
                cell_obj.currency
                or infer_currency_from_value(cell_obj.value)
                or infer_currency_from_value(cell_obj.cached_value)
            )
            if curr is not None and (
                isinstance(cell_obj.value, (int, float))
                or cell_obj.formula is not None
                or infer_currency_from_value(cell_obj.value) is not None
                or infer_currency_from_value(cell_obj.cached_value) is not None
            ):
                return {curr}
            if cell_obj.formula is not None:
                inherited: set[str] = set()
                for t_sh, sub_coords in evaluator.range_refs_by_cell.get(key, ()):
                    for sub_c in sub_coords:
                        inherited |= _cell_currencies(t_sh, sub_c, visited)
                for t_sh, sub_c in evaluator.cell_refs_by_cell.get(key, ()):
                    inherited |= _cell_currencies(t_sh, sub_c, visited)
                return inherited
            return set()

        for (owner_sheet, owner_coord), range_refs in evaluator.range_refs_by_cell.items():
            for target_sheet, coords in range_refs:
                sh = sheet_map.get(target_sheet)
                if sh is None:
                    continue
                currencies_seen: set[str] = set()
                for c in coords:
                    currencies_seen |= _cell_currencies(target_sheet, c, set())
                if len(currencies_seen) > 1:
                    detail = (
                        f"Mixed currencies {sorted(currencies_seen)} in range referenced by "
                        f"{owner_sheet}!{owner_coord} ({target_sheet}!{coords[0]}:{coords[-1]})"
                    )
                    mixed_details.append(detail)
                    flagged_owners.add((owner_sheet, owner_coord))

        all_owners = sorted(set(evaluator.range_refs_by_cell) | set(evaluator.cell_refs_by_cell))
        for owner_sheet, owner_coord in all_owners:
            if (owner_sheet, owner_coord) in flagged_owners:
                continue
            owner_currencies: set[str] = set()
            for target_sheet, coords in evaluator.range_refs_by_cell.get(
                (owner_sheet, owner_coord), ()
            ):
                for c in coords:
                    owner_currencies |= _cell_currencies(target_sheet, c, set())
            for target_sheet, c in evaluator.cell_refs_by_cell.get((owner_sheet, owner_coord), ()):
                owner_currencies |= _cell_currencies(target_sheet, c, set())
            if len(owner_currencies) > 1:
                mixed_details.append(
                    f"Mixed currencies {sorted(owner_currencies)} in cells referenced by "
                    f"{owner_sheet}!{owner_coord}"
                )

        # Also check per-column numeric currency consistency on each sheet
        for sheet in sheets:
            by_col: dict[int, set[str]] = {}
            for cell in sheet.cells.values():
                if cell.formula is not None:
                    continue
                is_numeric_like = isinstance(cell.value, (int, float)) or (
                    isinstance(cell.value, str)
                    and any(ch.isdigit() for ch in cell.value)
                    and infer_currency_from_value(cell.value) is not None
                )
                if not is_numeric_like:
                    continue
                curr = cell.currency or infer_currency_from_value(cell.value)
                if curr is not None:
                    by_col.setdefault(cell.col, set()).add(curr)
            for col_idx, currs in sorted(by_col.items()):
                if len(currs) > 1:
                    detail = (
                        f"Mixed currencies {sorted(currs)} in column {col_idx} "
                        f"of sheet {sheet.name!r}"
                    )
                    if detail not in mixed_details:
                        mixed_details.append(detail)

        mixed_detected = bool(mixed_details)
        errors.extend(mixed_details)

        passed = len(errors) == 0
        verdict = VerdictState.VERIFIED if passed else VerdictState.CONTRADICTED
        badge = (
            f"Fórmulas recalculadas: {formulas_ok}/{formulas_total} OK"
            if passed
            else f"Fórmulas con error: {formulas_ok}/{formulas_total} OK"
        )

        return SpreadsheetVerificationReport(
            passed=passed,
            verdict=verdict,
            formulas_total=formulas_total,
            formulas_ok=formulas_ok,
            recalc_engine=recalc_engine,
            badge=badge,
            errors=tuple(errors),
            mixed_currencies_detected=mixed_detected,
            mixed_currency_details=tuple(mixed_details),
            evaluated_values=evaluated_values,
        )


__all__ = [
    "EXCEL_ERROR_TOKENS",
    "ExcelFormulaEvalError",
    "SpreadsheetVerificationReport",
    "SpreadsheetVerifier",
]
