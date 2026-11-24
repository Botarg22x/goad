from __future__ import annotations

import itertools
import re
from dataclasses import dataclass


BUILTIN_CHARSETS: dict[str, str] = {
    "d": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

CUSTOM_CHARSET_TOKENS = frozenset({"1", "2", "3", "4"})
MASK_TOKEN_RE = re.compile(r"\?([A-Za-z0-9?])")


@dataclass(frozen=True)
class MaskExpansionResult:
    values: tuple[str, ...]
    total_count: int = 1
    truncated: bool = False
    missing_custom_charsets: tuple[str, ...] = ()
    unknown_tokens: tuple[str, ...] = ()


def expand_masked_value(
    value: str,
    custom_charsets: dict[str, str],
    limit: int,
) -> MaskExpansionResult:
    parts: list[str | tuple[str, ...]] = []
    total_count = 1
    missing: list[str] = []
    unknown: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "?" or index + 1 >= len(value):
            parts.append(char)
            index += 1
            continue

        token = value[index + 1]
        if token == "?":
            parts.append("?")
        elif token in BUILTIN_CHARSETS:
            charset = _unique_chars(BUILTIN_CHARSETS[token])
            parts.append(charset)
            total_count *= len(charset)
        elif token in CUSTOM_CHARSET_TOKENS:
            charset = _unique_chars(custom_charsets.get(token, ""))
            if charset:
                parts.append(charset)
                total_count *= len(charset)
            else:
                missing.append(token)
        else:
            unknown.append(token)
        index += 2

    if missing or unknown:
        return MaskExpansionResult((), total_count, False, tuple(dict.fromkeys(missing)), tuple(dict.fromkeys(unknown)))

    if not any(isinstance(part, tuple) for part in parts):
        return MaskExpansionResult((value,), total_count)

    values: list[str] = []
    truncated = False
    iterables: list[tuple[str, ...]] = [part if isinstance(part, tuple) else (part,) for part in parts]
    for combination in itertools.product(*iterables):
        values.append("".join(combination))
        if len(values) >= limit:
            truncated = total_count > limit
            break
    return MaskExpansionResult(tuple(values), total_count, truncated)


def required_custom_charsets(patterns: tuple[str, ...]) -> tuple[str, ...]:
    required: list[str] = []
    for pattern in patterns:
        for token in mask_tokens(pattern):
            if token in CUSTOM_CHARSET_TOKENS and token not in required:
                required.append(token)
    return tuple(required)


def unknown_mask_tokens(pattern: str) -> tuple[str, ...]:
    known = set(BUILTIN_CHARSETS) | CUSTOM_CHARSET_TOKENS | {"?"}
    return tuple(dict.fromkeys(token for token in mask_tokens(pattern) if token not in known))


def mask_tokens(pattern: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in MASK_TOKEN_RE.finditer(pattern))


def _unique_chars(value: str) -> tuple[str, ...]:
    chars: list[str] = []
    for char in value:
        if char not in chars:
            chars.append(char)
    return tuple(chars)
