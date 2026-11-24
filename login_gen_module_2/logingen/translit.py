from __future__ import annotations

import re
from heapq import heappop, heappush
from collections.abc import Mapping


_VALID_LOGIN_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_REPEATED_SEPARATORS = re.compile(r"([._-])\1+")


def normalize_lookup_key(value: str) -> str:
    return value.strip().lower()


def normalize_login(value: str, case: str = "lower") -> str:
    value = value.strip()
    if case == "lower":
        value = value.lower()
    elif case == "upper":
        value = value.upper()

    value = value.replace(" ", "")
    value = _VALID_LOGIN_CHARS.sub("", value)
    value = _REPEATED_SEPARATORS.sub(r"\1", value)
    return value.strip("._-")


def transliterate_variants(
    value: str,
    table: Mapping[str, str | list[str] | tuple[str, ...]],
    max_variants: int = 16,
) -> tuple[str, ...]:
    choices = tuple(_char_replacements(char, table) for char in value.strip())
    initial = (0,) * len(choices)
    pending = [(0, initial)]
    seen_indices = {initial}
    normalized: list[str] = []
    seen_values: set[str] = set()
    while pending and len(normalized) < max_variants:
        cost, indices = heappop(pending)
        cleaned = normalize_login("".join(options[index] for options, index in zip(choices, indices)))
        if cleaned and cleaned not in seen_values:
            normalized.append(cleaned)
            seen_values.add(cleaned)
        for position, index in enumerate(indices):
            if index + 1 >= len(choices[position]):
                continue
            next_indices = indices[:position] + (index + 1,) + indices[position + 1 :]
            if next_indices not in seen_indices:
                seen_indices.add(next_indices)
                heappush(pending, (cost + 1, next_indices))
    return tuple(normalized) or ("",)


def _char_replacements(
    char: str,
    table: Mapping[str, str | list[str] | tuple[str, ...]],
) -> tuple[str, ...]:
    lowered = char.lower()
    raw = table.get(lowered)
    if raw is None:
        if lowered.isascii() and (lowered.isalnum() or lowered in "._-"):
            return (lowered,)
        if lowered in {" ", "\t", "'", "`", "’", "ʼ"}:
            return ("",)
        if lowered == "-":
            return ("-",)
        return ("",)
    if isinstance(raw, str):
        return (raw.lower(),)
    values = tuple(str(item).lower() for item in raw)
    return values or ("",)
