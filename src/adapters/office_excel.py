"""Dynamic openpyxl + pure-stdlib OOXML (.xlsx) workbook builder and safe XML reader (CB-09)."""

from __future__ import annotations

import codecs
import importlib
import importlib.util
import os
import re
import uuid
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr

_XML_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XML_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_DTD_OR_ENTITY_RE = re.compile(rb"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_DTD_OR_ENTITY_TEXT_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XML_DECL_ENCODING_RE = re.compile(
    r"""encoding\s*=\s*["']([A-Za-z0-9._-]+)["']""",
    re.IGNORECASE,
)
_COORD_RE = re.compile(r"^(\$?)([A-Z]+)(\$?)(\d+)$", re.IGNORECASE)

_CURRENCY_FORMAT_CODES: dict[str, str] = {
    "USD": "$#,##0.00",
    "EUR": "€#,##0.00",
    "MXN": '"MXN "#,##0.00',
    "GBP": "£#,##0.00",
}


def col_index_to_letter(col_idx: int) -> str:
    """Convert 1-based column index to Excel column letters (1 -> A, 27 -> AA)."""
    if col_idx < 1:
        raise ValueError(f"Column index must be >= 1, got {col_idx}")
    letters: list[str] = []
    n = col_idx
    while n > 0:
        n, rem = divmod(n - 1, 26)
        letters.append(chr(65 + rem))
    return "".join(reversed(letters))


def letter_to_col_index(letters: str) -> int:
    """Convert Excel column letters to 1-based column index."""
    clean = letters.strip().upper()
    if not clean or not clean.isalpha():
        raise ValueError(f"Invalid column letters: {letters!r}")
    idx = 0
    for ch in clean:
        idx = idx * 26 + (ord(ch) - 64)
    return idx


def parse_cell_coord(coord: str) -> tuple[int, int]:
    """Parse A1 / $A$1 coordinate into (row, col) 1-based integers."""
    match = _COORD_RE.fullmatch(coord.strip())
    if match is None:
        raise ValueError(f"Invalid cell coordinate: {coord!r}")
    col_letters = match.group(2)
    row_num = int(match.group(4))
    return row_num, letter_to_col_index(col_letters)


def format_cell_coord(row: int, col: int) -> str:
    """Format 1-based (row, col) into Excel A1 coordinate."""
    return f"{col_index_to_letter(col)}{row}"


def infer_currency_from_format(format_code: str | None) -> str | None:
    """Detect currency code from Excel number format string."""
    if not format_code:
        return None
    upper = format_code.upper()
    if "EUR" in upper or "€" in format_code:
        return "EUR"
    if "MXN" in upper:
        return "MXN"
    if "GBP" in upper or "£" in format_code:
        return "GBP"
    if "USD" in upper or "$" in format_code:
        return "USD"
    return None


def infer_currency_from_value(value: Any) -> str | None:
    """Detect explicit currency prefix/suffix in a string cell value."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    upper = s.upper()
    if "EUR" in upper or "€" in s:
        return "EUR"
    if "MXN" in upper:
        return "MXN"
    if "GBP" in upper or "£" in s:
        return "GBP"
    if "USD" in upper or s.startswith("$"):
        return "USD"
    return None


class ExcelCellSpec(FrozenModel):
    """Cell specification supporting literal values, Excel formulas, and currency formats."""

    row: int = Field(ge=1)
    col: int = Field(ge=1)
    value: str | int | float | None = None
    formula: str | None = None
    currency: str | None = None
    number_format: str | None = None


class ExcelSheetSpec(FrozenModel):
    """Worksheet specification for OfficeExcelBuilder."""

    name: NonEmptyStr
    headers: tuple[str, ...] = ()
    rows: tuple[tuple[str | int | float | None, ...], ...] = ()
    formula_cells: tuple[ExcelCellSpec, ...] = ()
    extra_cells: tuple[ExcelCellSpec, ...] = ()
    currency_columns: dict[int, str] = Field(default_factory=dict)


class ExcelBuildResult(FrozenModel):
    """Build output metadata from OfficeExcelBuilder.build_workbook()."""

    path: Path
    formula_count: int = Field(ge=0)
    sheet_count: int = Field(ge=1)
    writer_backend: Literal["openpyxl", "ooxml_stdlib"]


class ParsedExcelCell(FrozenModel):
    """Parsed cell extracted safely from an OOXML .xlsx file."""

    coord: NonEmptyStr
    row: int = Field(ge=1)
    col: int = Field(ge=1)
    value: str | int | float | None = None
    formula: str | None = None
    cached_value: str | int | float | None = None
    data_type: str | None = None
    currency: str | None = None
    number_format: str | None = None


class ParsedExcelSheet(FrozenModel):
    """Parsed worksheet from an OOXML .xlsx file."""

    name: NonEmptyStr
    cells: dict[str, ParsedExcelCell] = Field(default_factory=dict)


def _decode_xml_bytes_for_scan(raw_bytes: bytes) -> str:
    if raw_bytes.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return raw_bytes.decode("utf-32", errors="replace")
    if raw_bytes.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw_bytes.decode("utf-16", errors="replace")
    if raw_bytes.startswith(codecs.BOM_UTF8):
        return raw_bytes.decode("utf-8-sig", errors="replace")
    if raw_bytes.startswith(b"\x00\x00\x00<"):
        return raw_bytes.decode("utf-32-be", errors="replace")
    if raw_bytes.startswith(b"<\x00\x00\x00"):
        return raw_bytes.decode("utf-32-le", errors="replace")
    if raw_bytes.startswith(b"\x00<\x00") or b"\x00<\x00" in raw_bytes[:64]:
        return raw_bytes.decode("utf-16-be", errors="replace")
    if raw_bytes.startswith(b"<\x00") or b"<\x00" in raw_bytes[:64]:
        return raw_bytes.decode("utf-16-le", errors="replace")
    probe = raw_bytes[:256].decode("ascii", errors="ignore")
    m_enc = _XML_DECL_ENCODING_RE.search(probe)
    if m_enc:
        try:
            return raw_bytes.decode(m_enc.group(1), errors="replace")
        except LookupError:
            pass
    return raw_bytes.decode("utf-8", errors="replace")


def _xml_safe_fromstring(raw_bytes: bytes, *, entry_name: str) -> ET.Element:
    decoded_text = _decode_xml_bytes_for_scan(raw_bytes)
    if (
        _DTD_OR_ENTITY_RE.search(raw_bytes) is not None
        or _DTD_OR_ENTITY_RE.search(raw_bytes.replace(b"\x00", b"")) is not None
        or _DTD_OR_ENTITY_TEXT_RE.search(decoded_text) is not None
    ):
        raise ValueError(
            f"Rejected unsafe XML in {entry_name!r}: DTD/ENTITY declarations are forbidden."
        )
    expat_parser = expat.ParserCreate()

    def _reject_dtd(*_args: Any, **_kwargs: Any) -> None:
        raise ValueError(
            f"Rejected unsafe XML in {entry_name!r}: DTD/ENTITY declarations are forbidden."
        )

    expat_parser.StartDoctypeDeclHandler = _reject_dtd
    expat_parser.EntityDeclHandler = _reject_dtd
    expat_parser.UnparsedEntityDeclHandler = _reject_dtd
    expat_parser.NotationDeclHandler = _reject_dtd
    expat_parser.ExternalEntityRefHandler = lambda *_a, **_kw: False
    expat_parser.Parse(raw_bytes, True)
    return ET.fromstring(raw_bytes)


def _normalize_formula(formula: str) -> str:
    stripped = formula.strip()
    return stripped[1:].strip() if stripped.startswith("=") else stripped


def _coerce_numeric_or_str(raw_text: str | None) -> str | int | float | None:
    if raw_text is None:
        return None
    stripped = raw_text.strip()
    if stripped == "":
        return None
    if stripped.startswith("#"):
        return stripped
    try:
        if "." not in stripped and "e" not in stripped.lower():
            return int(stripped)
        return float(stripped)
    except ValueError:
        return raw_text


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def read_workbook_ooxml(path: Path) -> list[ParsedExcelSheet]:
    """Safely read an .xlsx OOXML archive into structured sheets/cells/formulas/styles."""
    if not path.is_file():
        raise FileNotFoundError(f"Workbook not found: {path}")

    sheets_out: list[ParsedExcelSheet] = []
    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())

        # 1. Shared strings
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in names:
            ss_root = _xml_safe_fromstring(
                zf.read("xl/sharedStrings.xml"),
                entry_name="xl/sharedStrings.xml",
            )
            for si in ss_root:
                if _strip_ns(si.tag) != "si":
                    continue
                parts = [elem.text or "" for elem in si.iter() if _strip_ns(elem.tag) == "t"]
                shared_strings.append("".join(parts))

        # 2. Styles (numFmts + cellXfs)
        num_fmts: dict[int, str] = {
            164: "$#,##0.00",
        }
        cell_xf_num_fmts: list[int] = []
        if "xl/styles.xml" in names:
            st_root = _xml_safe_fromstring(zf.read("xl/styles.xml"), entry_name="xl/styles.xml")
            for child in st_root:
                cname = _strip_ns(child.tag)
                if cname == "numFmts":
                    for nf in child:
                        if _strip_ns(nf.tag) == "numFmt":
                            fid_str = nf.attrib.get("numFmtId")
                            fcode = nf.attrib.get("formatCode", "")
                            if fid_str and fid_str.isdigit():
                                num_fmts[int(fid_str)] = fcode
                elif cname == "cellXfs":
                    for xf in child:
                        if _strip_ns(xf.tag) == "xf":
                            fid_str = xf.attrib.get("numFmtId", "0")
                            cell_xf_num_fmts.append(int(fid_str) if fid_str.isdigit() else 0)

        # 3. Sheet name -> path resolution
        sheet_entries: list[tuple[str, str]] = []
        if "xl/workbook.xml" in names:
            wb_root = _xml_safe_fromstring(zf.read("xl/workbook.xml"), entry_name="xl/workbook.xml")
            rel_targets: dict[str, str] = {}
            if "xl/_rels/workbook.xml.rels" in names:
                rels_root = _xml_safe_fromstring(
                    zf.read("xl/_rels/workbook.xml.rels"),
                    entry_name="xl/_rels/workbook.xml.rels",
                )
                for rel in rels_root:
                    if _strip_ns(rel.tag) == "Relationship":
                        rid = rel.attrib.get("Id", "")
                        target = rel.attrib.get("Target", "")
                        if rid and target:
                            norm_target = target.lstrip("/")
                            if not norm_target.startswith("xl/"):
                                norm_target = f"xl/{norm_target}"
                            rel_targets[rid] = norm_target

            sheet_idx = 0
            for elem in wb_root.iter():
                if _strip_ns(elem.tag) == "sheet":
                    sheet_idx += 1
                    sname = elem.attrib.get("name", f"Sheet{sheet_idx}")
                    rid = elem.attrib.get(f"{{{_XML_NS_REL}}}id", "") or elem.attrib.get("r:id", "")
                    target_path = rel_targets.get(rid, f"xl/worksheets/sheet{sheet_idx}.xml")
                    if target_path in names:
                        sheet_entries.append((sname, target_path))

        if not sheet_entries:
            ws_paths = sorted(
                n for n in names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
            )
            for idx, ws_path in enumerate(ws_paths, start=1):
                sheet_entries.append((f"Sheet{idx}", ws_path))

        # 4. Parse worksheet XMLs
        for sname, ws_path in sheet_entries:
            ws_root = _xml_safe_fromstring(zf.read(ws_path), entry_name=ws_path)
            cells: dict[str, ParsedExcelCell] = {}
            for elem in ws_root.iter():
                if _strip_ns(elem.tag) != "c":
                    continue
                coord = elem.attrib.get("r", "").strip().upper()
                if not coord:
                    continue
                row_num, col_num = parse_cell_coord(coord)
                ctype = elem.attrib.get("t")
                style_idx_str = elem.attrib.get("s")
                fmt_code: str | None = None
                if style_idx_str and style_idx_str.isdigit():
                    s_idx = int(style_idx_str)
                    if 0 <= s_idx < len(cell_xf_num_fmts):
                        fmt_id = cell_xf_num_fmts[s_idx]
                        fmt_code = num_fmts.get(fmt_id)
                        if fmt_code is None and fmt_id in {44, 164}:
                            fmt_code = "$#,##0.00"

                formula_txt: str | None = None
                raw_v_txt: str | None = None
                inline_txt: str | None = None
                for sub in elem:
                    sub_name = _strip_ns(sub.tag)
                    if sub_name == "f" and sub.text is not None:
                        formula_txt = sub.text.strip()
                    elif sub_name == "v" and sub.text is not None:
                        raw_v_txt = sub.text
                    elif sub_name == "is":
                        t_parts = [
                            t_el.text or "" for t_el in sub.iter() if _strip_ns(t_el.tag) == "t"
                        ]
                        inline_txt = "".join(t_parts)

                resolved_val: str | int | float | None = None
                if ctype == "inlineStr":
                    resolved_val = inline_txt
                elif ctype == "s" and raw_v_txt is not None and raw_v_txt.isdigit():
                    s_pos = int(raw_v_txt)
                    resolved_val = (
                        shared_strings[s_pos] if 0 <= s_pos < len(shared_strings) else raw_v_txt
                    )
                elif ctype in {"str", "e"}:
                    resolved_val = raw_v_txt
                elif ctype == "b":
                    resolved_val = 1 if raw_v_txt == "1" else 0
                else:
                    resolved_val = _coerce_numeric_or_str(raw_v_txt)

                cached_val = resolved_val if formula_txt is not None else None
                currency = infer_currency_from_format(fmt_code) or infer_currency_from_value(
                    resolved_val
                )
                cells[coord] = ParsedExcelCell(
                    coord=coord,
                    row=row_num,
                    col=col_num,
                    value=None if formula_txt is not None else resolved_val,
                    formula=formula_txt,
                    cached_value=cached_val,
                    data_type=ctype,
                    currency=currency,
                    number_format=fmt_code,
                )
            sheets_out.append(ParsedExcelSheet(name=sname, cells=cells))

    return sheets_out


class OfficeExcelBuilder:
    """Creates genuine OOXML .xlsx workbooks via dynamic openpyxl or pure-stdlib fallback."""

    @staticmethod
    def has_openpyxl() -> bool:
        return importlib.util.find_spec("openpyxl") is not None

    def build_workbook(
        self,
        sheets: Sequence[ExcelSheetSpec],
        output_path: Path,
        *,
        force_stdlib: bool = False,
    ) -> ExcelBuildResult:
        if not sheets:
            raise ValueError("At least one ExcelSheetSpec is required.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex[:8]}.tmp")

        if not force_stdlib and self.has_openpyxl():
            formula_count = self._build_with_openpyxl(sheets, tmp_path)
            os.replace(tmp_path, output_path)
            return ExcelBuildResult(
                path=output_path,
                formula_count=formula_count,
                sheet_count=len(sheets),
                writer_backend="openpyxl",
            )

        formula_count = self._build_with_stdlib_ooxml(sheets, tmp_path)
        os.replace(tmp_path, output_path)
        return ExcelBuildResult(
            path=output_path,
            formula_count=formula_count,
            sheet_count=len(sheets),
            writer_backend="ooxml_stdlib",
        )

    @staticmethod
    def _build_with_openpyxl(sheets: Sequence[ExcelSheetSpec], target_path: Path) -> int:
        openpyxl_mod: Any = importlib.import_module("openpyxl")
        wb: Any = openpyxl_mod.Workbook()
        # Remove default sheet after creating specs
        default_ws = wb.active
        formula_count = 0

        for idx, sheet_spec in enumerate(sheets):
            ws = default_ws if idx == 0 else wb.create_sheet(title=sheet_spec.name)
            ws.title = sheet_spec.name
            row_offset = 1
            if sheet_spec.headers:
                for col_idx, hdr in enumerate(sheet_spec.headers, start=1):
                    ws.cell(row=1, column=col_idx, value=hdr)
                row_offset = 2

            for r_off, row_vals in enumerate(sheet_spec.rows):
                r_num = row_offset + r_off
                for c_idx, cell_val in enumerate(row_vals, start=1):
                    cell = ws.cell(row=r_num, column=c_idx, value=cell_val)
                    col_currency = sheet_spec.currency_columns.get(c_idx)
                    if col_currency and col_currency.upper() in _CURRENCY_FORMAT_CODES:
                        cell.number_format = _CURRENCY_FORMAT_CODES[col_currency.upper()]

            for spec_cell in (*sheet_spec.extra_cells, *sheet_spec.formula_cells):
                if spec_cell.formula is not None:
                    norm_f = _normalize_formula(spec_cell.formula)
                    cell = ws.cell(row=spec_cell.row, column=spec_cell.col, value=f"={norm_f}")
                    formula_count += 1
                else:
                    cell = ws.cell(row=spec_cell.row, column=spec_cell.col, value=spec_cell.value)
                fmt = spec_cell.number_format or (
                    _CURRENCY_FORMAT_CODES.get(spec_cell.currency.upper())
                    if spec_cell.currency
                    else None
                )
                if fmt:
                    cell.number_format = fmt

        wb.save(str(target_path))
        return formula_count

    @staticmethod
    def _build_with_stdlib_ooxml(sheets: Sequence[ExcelSheetSpec], target_path: Path) -> int:
        # Build style table: xf 0 = General, xf 1..N = custom formats
        custom_formats: dict[str, int] = {}
        format_id_by_xf: list[int] = [0]

        def _style_index_for_format(fmt: str | None) -> int:
            if not fmt:
                return 0
            if fmt not in custom_formats:
                num_fmt_id = 164 + len(custom_formats)
                custom_formats[fmt] = num_fmt_id
                format_id_by_xf.append(num_fmt_id)
            target_id = custom_formats[fmt]
            return format_id_by_xf.index(target_id)

        sheet_xmls: list[tuple[str, bytes]] = []
        formula_count = 0

        for idx, sheet_spec in enumerate(sheets, start=1):
            cell_map: dict[tuple[int, int], tuple[str | int | float | None, str | None, int]] = {}
            row_offset = 1
            if sheet_spec.headers:
                for col_idx, hdr in enumerate(sheet_spec.headers, start=1):
                    cell_map[(1, col_idx)] = (hdr, None, 0)
                row_offset = 2

            for r_off, row_vals in enumerate(sheet_spec.rows):
                r_num = row_offset + r_off
                for c_idx, cell_val in enumerate(row_vals, start=1):
                    col_currency = sheet_spec.currency_columns.get(c_idx)
                    fmt = _CURRENCY_FORMAT_CODES.get(col_currency.upper()) if col_currency else None
                    cell_map[(r_num, c_idx)] = (cell_val, None, _style_index_for_format(fmt))

            for spec_cell in (*sheet_spec.extra_cells, *sheet_spec.formula_cells):
                fmt = spec_cell.number_format or (
                    _CURRENCY_FORMAT_CODES.get(spec_cell.currency.upper())
                    if spec_cell.currency
                    else None
                )
                s_idx = _style_index_for_format(fmt)
                if spec_cell.formula is not None:
                    norm_f = _normalize_formula(spec_cell.formula)
                    cell_map[(spec_cell.row, spec_cell.col)] = (spec_cell.value, norm_f, s_idx)
                    formula_count += 1
                else:
                    cell_map[(spec_cell.row, spec_cell.col)] = (spec_cell.value, None, s_idx)

            ws_el = ET.Element("worksheet", {"xmlns": _XML_NS_MAIN})
            sheet_data = ET.SubElement(ws_el, "sheetData")
            rows_grouped: dict[
                int, list[tuple[int, str | int | float | None, str | None, int]]
            ] = {}
            for (r_num, c_idx), (val, formula_str, s_idx) in sorted(cell_map.items()):
                rows_grouped.setdefault(r_num, []).append((c_idx, val, formula_str, s_idx))

            for r_num in sorted(rows_grouped.keys()):
                row_el = ET.SubElement(sheet_data, "row", {"r": str(r_num)})
                for c_idx, val, formula_str, s_idx in sorted(
                    rows_grouped[r_num], key=lambda x: x[0]
                ):
                    coord = format_cell_coord(r_num, c_idx)
                    attrs: dict[str, str] = {"r": coord}
                    if s_idx > 0:
                        attrs["s"] = str(s_idx)

                    if formula_str is not None:
                        c_el = ET.SubElement(row_el, "c", attrs)
                        f_el = ET.SubElement(c_el, "f")
                        f_el.text = formula_str
                        if val is not None:
                            v_el = ET.SubElement(c_el, "v")
                            v_el.text = str(val)
                    elif isinstance(val, bool):
                        attrs["t"] = "b"
                        c_el = ET.SubElement(row_el, "c", attrs)
                        v_el = ET.SubElement(c_el, "v")
                        v_el.text = "1" if val else "0"
                    elif isinstance(val, (int, float)):
                        c_el = ET.SubElement(row_el, "c", attrs)
                        v_el = ET.SubElement(c_el, "v")
                        v_el.text = str(val)
                    elif isinstance(val, str):
                        attrs["t"] = "inlineStr"
                        c_el = ET.SubElement(row_el, "c", attrs)
                        is_el = ET.SubElement(c_el, "is")
                        t_el = ET.SubElement(is_el, "t")
                        t_el.text = val
                    else:
                        ET.SubElement(row_el, "c", attrs)

            ws_bytes = ET.tostring(ws_el, encoding="utf-8", xml_declaration=True)
            sheet_xmls.append((f"xl/worksheets/sheet{idx}.xml", ws_bytes))

        # Styles XML
        styles_el = ET.Element("styleSheet", {"xmlns": _XML_NS_MAIN})
        num_fmts_el = ET.SubElement(styles_el, "numFmts", {"count": str(len(custom_formats))})
        for fmt_code, fmt_id in custom_formats.items():
            ET.SubElement(
                num_fmts_el,
                "numFmt",
                {"numFmtId": str(fmt_id), "formatCode": fmt_code},
            )
        fonts_el = ET.SubElement(styles_el, "fonts", {"count": "1"})
        ET.SubElement(fonts_el, "font")
        fills_el = ET.SubElement(styles_el, "fills", {"count": "1"})
        ET.SubElement(fills_el, "fill")
        borders_el = ET.SubElement(styles_el, "borders", {"count": "1"})
        ET.SubElement(borders_el, "border")
        xfs_el = ET.SubElement(styles_el, "cellXfs", {"count": str(len(format_id_by_xf))})
        for fmt_id in format_id_by_xf:
            xf_attrs = {
                "numFmtId": str(fmt_id),
                "fontId": "0",
                "fillId": "0",
                "borderId": "0",
            }
            if fmt_id > 0:
                xf_attrs["applyNumberFormat"] = "1"
            ET.SubElement(xfs_el, "xf", xf_attrs)
        styles_bytes = ET.tostring(styles_el, encoding="utf-8", xml_declaration=True)

        # Content Types
        ct_el = ET.Element(
            "Types",
            {"xmlns": "http://schemas.openxmlformats.org/package/2006/content-types"},
        )
        ET.SubElement(
            ct_el,
            "Default",
            {
                "Extension": "rels",
                "ContentType": "application/vnd.openxmlformats-package.relationships+xml",
            },
        )
        ET.SubElement(ct_el, "Default", {"Extension": "xml", "ContentType": "application/xml"})
        ET.SubElement(
            ct_el,
            "Override",
            {
                "PartName": "/xl/workbook.xml",
                "ContentType": (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
                ),
            },
        )
        ET.SubElement(
            ct_el,
            "Override",
            {
                "PartName": "/xl/styles.xml",
                "ContentType": (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"
                ),
            },
        )
        for ws_path, _ in sheet_xmls:
            ET.SubElement(
                ct_el,
                "Override",
                {
                    "PartName": f"/{ws_path}",
                    "ContentType": (
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
                    ),
                },
            )
        ct_bytes = ET.tostring(ct_el, encoding="utf-8", xml_declaration=True)

        # Root rels
        root_rels = ET.Element(
            "Relationships",
            {"xmlns": "http://schemas.openxmlformats.org/package/2006/relationships"},
        )
        ET.SubElement(
            root_rels,
            "Relationship",
            {
                "Id": "rId1",
                "Type": (
                    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
                ),
                "Target": "xl/workbook.xml",
            },
        )
        root_rels_bytes = ET.tostring(root_rels, encoding="utf-8", xml_declaration=True)

        # Workbook & workbook rels
        wb_el = ET.Element("workbook", {"xmlns": _XML_NS_MAIN, "xmlns:r": _XML_NS_REL})
        sheets_el = ET.SubElement(wb_el, "sheets")
        wb_rels = ET.Element(
            "Relationships",
            {"xmlns": "http://schemas.openxmlformats.org/package/2006/relationships"},
        )
        for idx, sheet_spec in enumerate(sheets, start=1):
            rid = f"rId{idx}"
            ET.SubElement(
                sheets_el,
                "sheet",
                {"name": sheet_spec.name, "sheetId": str(idx), "r:id": rid},
            )
            ET.SubElement(
                wb_rels,
                "Relationship",
                {
                    "Id": rid,
                    "Type": (
                        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
                    ),
                    "Target": f"worksheets/sheet{idx}.xml",
                },
            )
        ET.SubElement(
            wb_rels,
            "Relationship",
            {
                "Id": f"rId{len(sheets) + 1}",
                "Type": (
                    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
                ),
                "Target": "styles.xml",
            },
        )
        wb_bytes = ET.tostring(wb_el, encoding="utf-8", xml_declaration=True)
        wb_rels_bytes = ET.tostring(wb_rels, encoding="utf-8", xml_declaration=True)

        with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", ct_bytes)
            zf.writestr("_rels/.rels", root_rels_bytes)
            zf.writestr("xl/workbook.xml", wb_bytes)
            zf.writestr("xl/_rels/workbook.xml.rels", wb_rels_bytes)
            zf.writestr("xl/styles.xml", styles_bytes)
            for ws_path, ws_bytes in sheet_xmls:
                zf.writestr(ws_path, ws_bytes)

        return formula_count


__all__ = [
    "ExcelBuildResult",
    "ExcelCellSpec",
    "ExcelSheetSpec",
    "OfficeExcelBuilder",
    "ParsedExcelCell",
    "ParsedExcelSheet",
    "col_index_to_letter",
    "format_cell_coord",
    "infer_currency_from_format",
    "infer_currency_from_value",
    "letter_to_col_index",
    "parse_cell_coord",
    "read_workbook_ooxml",
]
