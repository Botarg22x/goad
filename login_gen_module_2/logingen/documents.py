"""Extract text from public documents without executing embedded content."""
from __future__ import annotations

import re
import csv
import io
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit
from zipfile import ZipFile

SUPPORTED_DOCUMENT_TYPES = ("pdf", "docx", "pptx", "xlsx", "odt", "odp", "ods", "txt", "csv")
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


def document_type(url: str) -> str:
    return Path(unquote(urlsplit(url).path)).suffix.lower().lstrip(".")


def detect_document_type(url: str, body: bytes, content_type: str = "") -> str:
    """Use signatures first; reject HTML error pages masquerading as documents."""
    if body.lstrip().startswith(b"%PDF"):
        return "pdf"
    suffix = document_type(url)
    if body.startswith(b"PK\x03\x04"):
        with ZipFile(io.BytesIO(body)) as archive:
            names = set(archive.namelist())
            if "word/document.xml" in names:
                return "docx"
            if "ppt/presentation.xml" in names:
                return "pptx"
            if "xl/workbook.xml" in names:
                return "xlsx"
            if "content.xml" in names and suffix in {"odt", "odp", "ods"}:
                return suffix
        return ""
    if suffix in {"txt", "csv"} and "html" not in content_type.lower():
        if not re.search(br"<(?:!doctype\s+html|html)\b", body[:1000], re.I):
            return suffix
    return ""


def extract_document_text(path: Path, *, pdf_extractor=None) -> str:
    kind = path.suffix.lower().lstrip(".")
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("документ больше 64 МиБ")
    if kind == "pdf":
        if pdf_extractor is None:
            from pdfminer.high_level import extract_text
            pdf_extractor = extract_text
        return pdf_extractor(path) or ""
    if kind in {"txt", "csv"}:
        data = path.read_bytes()
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = data.decode("cp1251")
        if kind == "csv":
            try:
                dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
            except csv.Error:
                return text
            return "\n".join(" ".join(row) for row in csv.reader(io.StringIO(text), dialect))
        return text
    if kind not in SUPPORTED_DOCUMENT_TYPES:
        raise ValueError(f"неподдерживаемый формат: {kind}")
    with ZipFile(path) as archive:
        if sum(entry.file_size for entry in archive.infolist()) > MAX_DOCUMENT_BYTES:
            raise ValueError("распакованный документ больше 64 МиБ")
        def xml(name):
            data = archive.read(name)
            if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
                raise ValueError("DTD в документе не поддерживается")
            return ET.fromstring(data)

        if kind == "xlsx":
            shared = []
            if "xl/sharedStrings.xml" in archive.namelist():
                shared = ["".join(node.itertext()) for node in xml("xl/sharedStrings.xml")]
            lines = []
            for name in sorted(archive.namelist()):
                if not re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name):
                    continue
                for row in xml(name).iter():
                    if _tag(row) != "row":
                        continue
                    cells = []
                    for cell in row:
                        value = "".join(cell.itertext())
                        if cell.get("t") == "s":
                            value = shared[int(value)]
                        cells.append(value)
                    lines.append(" ".join(cells))
            return "\n".join(lines)
        if kind == "docx":
            names = [name for name in archive.namelist() if re.fullmatch(
                r"word/(?:document|header\d+|footer\d+|footnotes|endnotes)\.xml", name)]
        elif kind == "pptx":
            names = [name for name in archive.namelist() if re.fullmatch(
                r"ppt/(?:slides/slide|notesSlides/notesSlide)\d+\.xml", name)]
        else:
            names = ["content.xml"]
        lines = []
        for name in sorted(names):
            for node in xml(name).iter():
                if _tag(node) in {"p", "h"}:
                    lines.append("".join(node.itertext()))
        return "\n".join(lines)


def _tag(node) -> str:
    return node.tag.rsplit("}", 1)[-1]
