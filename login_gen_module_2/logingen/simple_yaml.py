from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class _Line:
    indent: int
    text: str


def load_yaml_file(path: Path) -> dict[str, Any]:
    return loads(path.read_text(encoding="utf-8"))


def loads(source: str) -> dict[str, Any]:
    lines = _prepare_lines(source)
    if not lines:
        return {}
    value, index = _parse_block(lines, 0, lines[0].indent)
    if index != len(lines):
        raise ValueError(f"Unexpected YAML content near line {index + 1}")
    if not isinstance(value, dict):
        raise ValueError("Root YAML value must be a mapping")
    return value


def _prepare_lines(source: str) -> list[_Line]:
    result: list[_Line] = []
    for raw in source.splitlines():
        text = _strip_comment(raw.rstrip())
        if not text.strip():
            continue
        indent = len(text) - len(text.lstrip(" "))
        if "\t" in text[:indent]:
            raise ValueError("Tabs are not supported for YAML indentation")
        result.append(_Line(indent=indent, text=text.strip()))
    return result


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return line[:index].rstrip()
    return line


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    if lines[index].indent < indent:
        return {}, index
    if lines[index].text.startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise ValueError(f"Unexpected indentation near line {index + 1}")
        if line.text.startswith("- "):
            break

        key, raw_value = _split_key_value(line.text, index)
        index += 1
        if raw_value == "":
            if index < len(lines) and lines[index].indent > line.indent:
                value, index = _parse_block(lines, index, lines[index].indent)
            else:
                value = {}
        else:
            value = _parse_scalar(raw_value)
        mapping[key] = value
    return mapping, index


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list[Any], int]:
    sequence: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise ValueError(f"Unexpected indentation near line {index + 1}")
        if not line.text.startswith("- "):
            break

        item_text = line.text[2:].strip()
        index += 1
        if item_text == "":
            if index < len(lines) and lines[index].indent > line.indent:
                item, index = _parse_block(lines, index, lines[index].indent)
            else:
                item = None
            sequence.append(item)
            continue

        if _looks_like_mapping_item(item_text):
            key, raw_value = _split_key_value(item_text, index - 1)
            item: dict[str, Any] = {key: _parse_scalar(raw_value) if raw_value else {}}
            if index < len(lines) and lines[index].indent > line.indent:
                extra, index = _parse_mapping(lines, index, lines[index].indent)
                item.update(extra)
            sequence.append(item)
            continue

        sequence.append(_parse_scalar(item_text))
    return sequence, index


def _split_key_value(text: str, index: int) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"Expected key/value pair near line {index + 1}")
    key, value = text.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"Empty YAML key near line {index + 1}")
    return key, value.strip()


def _looks_like_mapping_item(text: str) -> bool:
    if ":" not in text:
        return False
    before, _after = text.split(":", 1)
    return bool(before.strip()) and " " not in before.strip()


def _parse_scalar(value: str) -> Any:
    if value == "":
        return ""
    lowered = value.lower()
    if lowered in {"null", "none", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if _is_quoted(value):
        return _unquote(value)
    if value.startswith("[") and value.endswith("]"):
        return _parse_inline_list(value[1:-1])
    try:
        return int(value)
    except ValueError:
        return value


def _is_quoted(value: str) -> bool:
    return len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}


def _unquote(value: str) -> str:
    if value[0] == '"':
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return value[1:-1].replace("''", "'")


def _parse_inline_list(value: str) -> list[Any]:
    if not value.strip():
        return []
    items: list[str] = []
    current = []
    quote: str | None = None
    for char in value:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ",":
            items.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    items.append("".join(current).strip())
    return [_parse_scalar(item) for item in items]
