"""Spreadsheet exports for collected evidence, without optional dependencies."""

from __future__ import annotations

import csv
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

ET.register_namespace("", MAIN_NS)
ET.register_namespace("r", DOC_REL_NS)

PERSON_COLUMNS = (
    ("ФИО", "value"), ("Тип источника", "source_type"),
    ("Ссылка на источник", "source_url"), ("Поисковый запрос", "query_url"),
    ("Сохранённая копия", "artifact_path"), ("Статус копии", "proof_status"),
    ("SHA-256 копии", "sha256"), ("Время сбора UTC", "collected_at"),
)
EMAIL_COLUMNS = (
    ("E-mail", "value"), ("Тип источника", "source_type"),
    ("Ссылка на источник", "source_url"), ("Ссылка из выдачи", "linked_url"),
    ("Поисковый запрос", "query_url"), ("Сохранённая копия", "artifact_path"),
    ("Статус копии", "proof_status"), ("SHA-256 копии", "sha256"),
    ("Время сбора UTC", "collected_at"),
)
LINK_KEYS = frozenset({"source_url", "linked_url", "query_url", "artifact_path"})


def write_evidence_tables(evidence_path: Path, records: list[dict[str, str]]) -> tuple[Path, Path]:
    """Write a FIO CSV and a two-sheet Excel book beside evidence.jsonl."""
    directory = evidence_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    people = [row for row in records if row.get("kind") == "person"]
    emails = [row for row in records if row.get("kind") == "email"]
    people_csv = directory / "fio_sources.csv"
    workbook = evidence_path.with_suffix(".xlsx")
    _write_csv(people_csv, PERSON_COLUMNS, people)
    _write_workbook(workbook, (("ФИО", PERSON_COLUMNS, people), ("E-mail", EMAIL_COLUMNS, emails)))
    return people_csv, workbook


def _write_csv(path: Path, columns: tuple[tuple[str, str], ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.writer(output)
        writer.writerow([heading for heading, _ in columns])
        writer.writerows([row.get(key, "") for _, key in columns] for row in rows)


def _write_workbook(
    path: Path,
    sheets: tuple[tuple[str, tuple[tuple[str, str], ...], list[dict[str, str]]], ...],
) -> None:
    with tempfile.NamedTemporaryFile(prefix=".evidence-", suffix=".xlsx", dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with ZipFile(temporary_path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", _content_types(len(sheets)))
            archive.writestr("_rels/.rels", _root_relationships())
            archive.writestr("xl/workbook.xml", _workbook_xml(sheets))
            archive.writestr("xl/_rels/workbook.xml.rels", _workbook_relationships(len(sheets)))
            for index, (_, columns, rows) in enumerate(sheets, start=1):
                sheet_xml, links_xml = _sheet_xml(columns, rows)
                archive.writestr(f"xl/worksheets/sheet{index}.xml", sheet_xml)
                if links_xml is not None:
                    archive.writestr(f"xl/worksheets/_rels/sheet{index}.xml.rels", links_xml)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _xml(element: ET.Element) -> bytes:
    return ET.tostring(element, encoding="utf-8", xml_declaration=True)


def _content_types(sheet_count: int) -> bytes:
    root = ET.Element(f"{{{CONTENT_NS}}}Types")
    ET.SubElement(root, f"{{{CONTENT_NS}}}Default", Extension="rels", ContentType="application/vnd.openxmlformats-package.relationships+xml")
    ET.SubElement(root, f"{{{CONTENT_NS}}}Default", Extension="xml", ContentType="application/xml")
    ET.SubElement(root, f"{{{CONTENT_NS}}}Override", PartName="/xl/workbook.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
    for index in range(1, sheet_count + 1):
        ET.SubElement(root, f"{{{CONTENT_NS}}}Override", PartName=f"/xl/worksheets/sheet{index}.xml", ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")
    return _xml(root)


def _root_relationships() -> bytes:
    root = ET.Element(f"{{{PACKAGE_REL_NS}}}Relationships")
    ET.SubElement(root, f"{{{PACKAGE_REL_NS}}}Relationship", Id="rId1", Type=f"{DOC_REL_NS}/officeDocument", Target="xl/workbook.xml")
    return _xml(root)


def _workbook_xml(sheets: tuple[tuple[str, tuple[tuple[str, str], ...], list[dict[str, str]]], ...]) -> bytes:
    root = ET.Element(f"{{{MAIN_NS}}}workbook")
    listed = ET.SubElement(root, f"{{{MAIN_NS}}}sheets")
    for index, (name, _, _) in enumerate(sheets, start=1):
        ET.SubElement(listed, f"{{{MAIN_NS}}}sheet", {"name": name, "sheetId": str(index), f"{{{DOC_REL_NS}}}id": f"rId{index}"})
    return _xml(root)


def _workbook_relationships(sheet_count: int) -> bytes:
    root = ET.Element(f"{{{PACKAGE_REL_NS}}}Relationships")
    for index in range(1, sheet_count + 1):
        ET.SubElement(root, f"{{{PACKAGE_REL_NS}}}Relationship", Id=f"rId{index}", Type=f"{DOC_REL_NS}/worksheet", Target=f"worksheets/sheet{index}.xml")
    return _xml(root)


def _sheet_xml(columns: tuple[tuple[str, str], ...], rows: list[dict[str, str]]) -> tuple[bytes, bytes | None]:
    root = ET.Element(f"{{{MAIN_NS}}}worksheet")
    data = ET.SubElement(root, f"{{{MAIN_NS}}}sheetData")
    links: list[tuple[str, str]] = []
    for row_number, values in enumerate(([heading for heading, _ in columns], *(
        [row.get(key, "") for _, key in columns] for row in rows
    )), start=1):
        row_element = ET.SubElement(data, f"{{{MAIN_NS}}}row", r=str(row_number))
        for column_number, value in enumerate(values, start=1):
            reference = f"{_column_name(column_number)}{row_number}"
            cell = ET.SubElement(row_element, f"{{{MAIN_NS}}}c", r=reference, t="inlineStr")
            inline = ET.SubElement(cell, f"{{{MAIN_NS}}}is")
            text = ET.SubElement(inline, f"{{{MAIN_NS}}}t")
            text.text = _excel_text(str(value))
            if row_number > 1 and value and columns[column_number - 1][1] in LINK_KEYS:
                target = _hyperlink_target(str(value), columns[column_number - 1][1])
                if target:
                    links.append((reference, target))
    if not links:
        return _xml(root), None
    listed = ET.SubElement(root, f"{{{MAIN_NS}}}hyperlinks")
    relationships = ET.Element(f"{{{PACKAGE_REL_NS}}}Relationships")
    for index, (reference, target) in enumerate(links, start=1):
        ET.SubElement(listed, f"{{{MAIN_NS}}}hyperlink", {"ref": reference, f"{{{DOC_REL_NS}}}id": f"rId{index}"})
        ET.SubElement(relationships, f"{{{PACKAGE_REL_NS}}}Relationship", Id=f"rId{index}", Type=f"{DOC_REL_NS}/hyperlink", Target=target, TargetMode="External")
    return _xml(root), _xml(relationships)


def _column_name(number: int) -> str:
    name = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _excel_text(value: str) -> str:
    return "".join(char for char in value[:32767] if ord(char) >= 32 or char in "\t\n\r")


def _hyperlink_target(value: str, key: str) -> str:
    if key == "artifact_path":
        artifact = Path(value)
        return artifact.resolve().as_uri() if artifact.is_file() else ""
    return value if value.startswith(("https://", "http://")) else ""
