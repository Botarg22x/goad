from __future__ import annotations

import re
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from .normalize import is_logout_url, normalize_url


MAX_STANDARD_PATHS = 2000
_BUILTIN_RESOURCE = ("data", "standard_paths.txt")
_DUMMY_ORIGIN = "https://standard-path.invalid"
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def load_standard_paths(path: Path | None) -> list[str]:
    """Load and validate a built-in or operator-supplied standard-path list."""
    if path is None:
        resource = files("authpoints").joinpath(*_BUILTIN_RESOURCE)
        text = resource.read_text(encoding="utf-8")
        label = "built-in standard paths"
    else:
        text = path.read_text(encoding="utf-8-sig")
        label = str(path)
    return _validate_path_lines(text, label=label)


def expand_standard_paths(origins: list[str], paths: list[str]) -> list[str]:
    """Expand validated paths against each unique HTTP(S) origin."""
    validated_paths = _validate_values(paths)
    normalized_origins: list[tuple[str, str]] = []
    seen_origins: set[tuple[str, str]] = set()
    for raw_origin in origins:
        normalized = normalize_url(raw_origin, redact_query=False)
        parts = urlsplit(normalized)
        origin = (parts.scheme, parts.netloc)
        if origin not in seen_origins:
            seen_origins.add(origin)
            normalized_origins.append(origin)

    expanded: list[str] = []
    for scheme, netloc in normalized_origins:
        for path in validated_paths:
            parts = urlsplit(path)
            expanded.append(
                urlunsplit((scheme, netloc, parts.path, parts.query, ""))
            )
    return expanded


def _validate_path_lines(text: str, *, label: str) -> list[str]:
    values: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.strip(" ")
        if not value or value.startswith("#"):
            continue
        try:
            values.append(_validate_path(value))
        except ValueError as exc:
            raise ValueError(f"{label}:{line_number}: {exc}") from exc
    return _deduplicate_and_limit(values)


def _validate_values(paths: list[str]) -> list[str]:
    values: list[str] = []
    for index, value in enumerate(paths, start=1):
        if not isinstance(value, str):
            raise ValueError(f"standard path {index} must be a string")
        try:
            values.append(_validate_path(value))
        except ValueError as exc:
            raise ValueError(f"standard path {index}: {exc}") from exc
    return _deduplicate_and_limit(values)


def _validate_path(value: str) -> str:
    if not value:
        raise ValueError("path is empty")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("path contains control characters")
    if any(character.isspace() for character in value):
        raise ValueError("path contains whitespace")
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("path must start with exactly one slash")
    if "\\" in value:
        raise ValueError("path contains a backslash")
    if _BAD_PERCENT_ESCAPE.search(value):
        raise ValueError("path contains an invalid percent escape")

    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        raise ValueError("absolute URLs are not allowed")
    if parts.username is not None or parts.password is not None:
        raise ValueError("userinfo is not allowed")
    if parts.fragment:
        raise ValueError("fragments are not allowed")

    decoded = value
    for _ in range(4):
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
            raise ValueError("path contains encoded control characters")
        normalized_separators = decoded.replace("\\", "/")
        if normalized_separators.startswith("//"):
            raise ValueError("encoded network-path references are not allowed")
        decoded_path = urlsplit(normalized_separators).path
        if any(segment.split(";", 1)[0] in {".", ".."} for segment in decoded_path.split("/")):
            raise ValueError("path traversal is not allowed")
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value

    absolute = _DUMMY_ORIGIN + value
    if is_logout_url(absolute):
        raise ValueError("logout paths are not allowed")
    return value


def _deduplicate_and_limit(values: list[str]) -> list[str]:
    unique = list(dict.fromkeys(values))
    if len(unique) > MAX_STANDARD_PATHS:
        raise ValueError(
            f"standard path list contains more than {MAX_STANDARD_PATHS} unique entries"
        )
    return unique
